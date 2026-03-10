"""Scanner for Claude Code (cowork) sessions.

Parses two session formats:
  - CLI sessions: ``~/.claude/projects/{project-slug}/{uuid}.jsonl``
    JSONL with ``type: "assistant"`` events containing ``tool_use`` content blocks.
  - Desktop sessions: ``~/Library/Application Support/Claude/local-agent-mode-sessions/``
    ``local_*.json`` metadata + ``{session_id}/audit.jsonl`` event logs.

Produces output compatible with the existing OutputSummary contract so the
backend receives the same JSON shape regardless of which variant was detected.
"""

import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from platform_compat.common import get_system_info
from scanner_utils import parse_skill_md, read_json_config
from scrubber import scrub_arguments, scrub_url
from structures import ClawdbotInstallInfo
from output_structures import OutputSkillEntry, OutputSummary, _EMPTY_MISSING


# =============================================================================
# CLI Session Discovery & Parsing
# =============================================================================

def _find_cli_session_files(config_dir: Path) -> List[Path]:
    """Find all ``*.jsonl`` files under ``~/.claude/projects/*/``."""
    projects_dir = config_dir / "projects"
    if not projects_dir.is_dir():
        return []
    return sorted(projects_dir.glob("*/*.jsonl"))


def _extract_app_name(command: str) -> Optional[str]:
    """Extract the primary program name from a shell command string.

    Strips leading env-var assignments, takes the first pipeline segment,
    and skips common wrapper commands (sudo, env, etc.).
    """
    cmd = command.strip()
    if not cmd:
        return None
    # Remove leading env variable assignments (VAR=val)
    while re.match(r'^[A-Z_]+=\S+\s', cmd):
        cmd = re.sub(r'^[A-Z_]+=\S+\s+', '', cmd, count=1)
    # Take first segment before pipe, &&, or ;
    cmd = re.split(r'\s*(?:[|;]|&&)\s*', cmd)[0].strip()
    tokens = cmd.split()
    if not tokens:
        return None
    prog = os.path.basename(tokens[0])
    # Skip wrappers → return the actual program
    if prog in ('sudo', 'env', 'time', 'nice', 'nohup', 'xargs', 'command'):
        if len(tokens) > 1:
            return os.path.basename(tokens[1])
    return prog


def _parse_cli_session(session_file: Path) -> List[Dict[str, Any]]:
    """Parse a CLI JSONL session file and extract tool_use events.

    Each line is a JSON object with ``type``, ``message.content[]``, etc.
    We look for ``type: "assistant"`` lines whose ``message.content`` contains
    blocks with ``type: "tool_use"``.

    Returns a list of tool-event dicts (tool_name, input, timestamp, session).
    """
    events: List[Dict[str, Any]] = []
    session_name = session_file.stem

    try:
        with open(session_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                # Quick check before parsing JSON
                if "tool_use" not in line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if data.get("type") != "assistant":
                    continue

                ts = data.get("timestamp", "")
                content = data.get("message", {}).get("content", [])
                if not isinstance(content, list):
                    continue

                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "tool_use":
                        continue
                    events.append({
                        "tool_name": block.get("name", "unknown"),
                        "input": block.get("input", {}),
                        "id": block.get("id", ""),
                        "timestamp": ts,
                        "session": session_name,
                    })
    except OSError:
        pass

    return events


# =============================================================================
# Desktop Session Discovery & Parsing
# =============================================================================

_DESKTOP_CANDIDATE_DIRS = [
    # macOS
    Path.home() / "Library" / "Application Support" / "Claude" / "local-agent-mode-sessions",
    # Linux
    Path.home() / ".config" / "Claude" / "local-agent-mode-sessions",
]


def _find_desktop_sessions_dir() -> Optional[Path]:
    """Auto-detect Claude Desktop sessions from known paths (macOS/Linux)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        candidate = Path(xdg) / "Claude" / "local-agent-mode-sessions"
        if candidate.is_dir():
            return candidate

    for candidate in _DESKTOP_CANDIDATE_DIRS:
        if candidate.is_dir():
            return candidate
    return None


def _discover_desktop_sessions(base_dir: Path) -> List[Dict[str, Any]]:
    """Parse Desktop ``local_*.json`` + ``audit.jsonl`` files.

    Each ``local_*.json`` is session metadata.  The corresponding
    ``{session_id}/audit.jsonl`` contains the event log.

    Returns list of dicts with ``meta``, ``audit``, ``session_id``.
    """
    sessions: List[Dict[str, Any]] = []
    if not base_dir.is_dir():
        return sessions

    for meta_file in sorted(base_dir.glob("**/local_*.json")):
        session_id = meta_file.stem  # e.g. "local_abc123"
        session_dir = meta_file.parent / session_id

        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            meta = {}

        audit_path = session_dir / "audit.jsonl"
        audit_events: List[Dict[str, Any]] = []
        if audit_path.exists():
            try:
                with open(audit_path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            try:
                                audit_events.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
            except OSError:
                pass

        sessions.append({
            "session_id": session_id,
            "meta": meta,
            "audit": audit_events,
        })

    return sessions


def _parse_desktop_tool_events(desktop_sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract tool_use events from Desktop audit logs.

    Desktop audit events have ``type: "assistant"`` with
    ``message.content[]`` blocks containing ``type: "tool_use"``.
    """
    events: List[Dict[str, Any]] = []
    seen_ids: set = set()

    for sess in desktop_sessions:
        session_id = sess["session_id"]
        title = (sess["meta"].get("title") or session_id[:20])[:40]

        for evt in sess["audit"]:
            if evt.get("type") != "assistant":
                continue
            content = evt.get("message", {}).get("content", [])
            if not isinstance(content, list):
                continue
            ts = evt.get("_audit_timestamp", evt.get("timestamp", ""))

            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                bid = block.get("id", "")
                if bid and bid in seen_ids:
                    continue
                if bid:
                    seen_ids.add(bid)

                events.append({
                    "tool_name": block.get("name", "unknown"),
                    "input": block.get("input", {}),
                    "id": bid,
                    "timestamp": ts,
                    "session": title,
                })

    return events


# =============================================================================
# Event Classification & Processing
# =============================================================================

def _classify_tool_events(
    tool_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Classify tool_use events into skills, apps, web activity, nodes, permissions.

    Mirrors the classification logic from ``cowork_report_exporter.build_summary``.
    """
    tool_counts: Counter = Counter()
    skills: List[OutputSkillEntry] = []
    skills_seen: set = set()

    apps: set = set()
    apps_call_count: Counter = Counter()
    apps_commands: Dict[str, List[Dict[str, str]]] = defaultdict(list)

    plugins_seen: set = set()
    plugins: List[Dict[str, Any]] = []

    browser_urls: List[Dict[str, str]] = []
    fetched_urls: List[Dict[str, str]] = []
    search_queries: List[Dict[str, str]] = []

    permissions: set = set()
    nodes: List[Dict[str, Any]] = []

    for evt in tool_events:
        tool_name = evt["tool_name"]
        inp = evt.get("input", {})
        if not isinstance(inp, dict):
            inp = {}
        ts = evt.get("timestamp", "")
        session = evt.get("session", "")
        tool_counts[tool_name] += 1

        # ── Skill tool ──
        if tool_name == "Skill":
            sk = str(inp.get("skill", "unknown"))
            if sk not in skills_seen:
                skills_seen.add(sk)
                skills.append({
                    "name": sk,
                    "description": "",
                    "emoji": None,
                    "eligible": True,
                    "disabled": False,
                    "blockedByAllowlist": False,
                    "source": "session_audit",
                    "bundled": False,
                    "primaryEnv": None,
                    "homepage": None,
                    "missing": _EMPTY_MISSING,
                })

        # ── Bash → apps + commands ──
        elif tool_name == "Bash":
            cmd = str(inp.get("command", ""))[:500]
            if cmd:
                app = _extract_app_name(cmd)
                if app:
                    apps.add(app)
                    apps_call_count[app] += 1
                    apps_commands[app].append({
                        "command": scrub_arguments(cmd) if isinstance(cmd, str) else cmd,
                        "timestamp": ts[:19] if ts else "",
                        "session": session,
                    })

        # ── WebFetch → fetched URLs ──
        elif tool_name == "WebFetch":
            url = inp.get("url", "")
            if url:
                fetched_urls.append({
                    "url": scrub_url(url),
                    "timestamp": ts[:19] if ts else "",
                    "session": session,
                })

        # ── WebSearch → search queries ──
        elif tool_name == "WebSearch":
            q = str(inp.get("query", ""))
            if q:
                search_queries.append({
                    "query": q[:200],
                    "timestamp": ts[:19] if ts else "",
                    "session": session,
                })

        # ── MCP tools → browser URLs if applicable ──
        elif tool_name.startswith("mcp__"):
            # Track MCP server as a plugin
            parts = tool_name.split("__", 2)
            if len(parts) >= 2:
                server_name = parts[1]
                if server_name not in plugins_seen:
                    plugins_seen.add(server_name)
                    plugins.append({
                        "name": server_name,
                        "source": "mcp",
                        "enabled": True,
                    })
                apps.add(server_name)

            if any(kw in tool_name.lower()
                   for kw in ("navigate", "browser", "goto", "open_url")):
                url = inp.get("url") or inp.get("href") or ""
                if url:
                    browser_urls.append({
                        "url": scrub_url(url),
                        "action": tool_name,
                        "timestamp": ts[:19] if ts else "",
                        "session": session,
                    })

        # ── Task → sub-agent nodes ──
        elif tool_name == "Task":
            nodes.append({
                "description": str(inp.get("description", ""))[:150],
                "type": str(inp.get("subagent_type", "")),
                "session": session,
                "timestamp": ts[:19] if ts else "",
            })

        # Track used permissions
        if tool_name in ("Read", "Write", "Edit", "Bash",
                         "WebFetch", "WebSearch", "Glob", "Grep"):
            permissions.add(tool_name.lower())

    # Cap command lists per app
    for app_key in apps_commands:
        apps_commands[app_key] = apps_commands[app_key][:100]

    return {
        "tool_counts": dict(tool_counts),
        "skills": skills,
        "apps": sorted(apps),
        "apps_call_count": dict(apps_call_count),
        "apps_commands": dict(apps_commands),
        "plugins": plugins,
        "browser_urls": browser_urls,
        "fetched_urls": fetched_urls,
        "search_queries": search_queries,
        "permissions": sorted(permissions),
        "nodes": nodes,
    }


def _build_agent_dict(classified: Dict[str, Any], sessions_scanned: int) -> Dict[str, Any]:
    """Build a per-agent output dict from classified tool events."""
    tool_counts = classified["tool_counts"]
    web_activity = {
        "browser_urls": classified["browser_urls"],
        "fetched_urls": classified["fetched_urls"],
        "search_queries": classified["search_queries"],
        "browser_urls_count": len(classified["browser_urls"]),
        "fetched_urls_count": len(classified["fetched_urls"]),
        "search_queries_count": len(classified["search_queries"]),
    }
    return {
        "sessions_scanned": sessions_scanned,
        "total_tool_calls": sum(tool_counts.values()),
        "tools_summary": tool_counts,
        "apps_summary": classified["apps_call_count"],
        "apps_commands": classified["apps_commands"],
        "web_activity": web_activity,
        "skills": classified["skills"],
        "plugins": classified["plugins"],
        "nodes": classified["nodes"],
        "permissions": classified["permissions"],
    }


def _merge_classified(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two classified-event dicts into one combined result."""
    merged_counts = Counter(a["tool_counts"])
    merged_counts.update(b["tool_counts"])

    # Skills – deduplicate by name
    seen_skills = {s["name"] for s in a["skills"]}
    merged_skills = list(a["skills"])
    for s in b["skills"]:
        if s["name"] not in seen_skills:
            seen_skills.add(s["name"])
            merged_skills.append(s)

    merged_apps = sorted(set(a["apps"]) | set(b["apps"]))

    merged_apps_count = Counter(a["apps_call_count"])
    merged_apps_count.update(b["apps_call_count"])

    merged_commands: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for k, v in a["apps_commands"].items():
        merged_commands[k].extend(v)
    for k, v in b["apps_commands"].items():
        merged_commands[k].extend(v)
    for k in merged_commands:
        merged_commands[k] = merged_commands[k][:100]

    # Plugins – deduplicate by name
    seen_plugins = {p["name"] for p in a["plugins"]}
    merged_plugins = list(a["plugins"])
    for p in b["plugins"]:
        if p["name"] not in seen_plugins:
            seen_plugins.add(p["name"])
            merged_plugins.append(p)

    return {
        "tool_counts": dict(merged_counts),
        "skills": merged_skills,
        "apps": merged_apps,
        "apps_call_count": dict(merged_apps_count),
        "apps_commands": dict(merged_commands),
        "plugins": merged_plugins,
        "browser_urls": a["browser_urls"] + b["browser_urls"],
        "fetched_urls": a["fetched_urls"] + b["fetched_urls"],
        "search_queries": a["search_queries"] + b["search_queries"],
        "permissions": sorted(set(a["permissions"]) | set(b["permissions"])),
        "nodes": a["nodes"] + b["nodes"],
    }


# =============================================================================
# Settings & Plugins Scanning
# =============================================================================

def _scan_settings(config_dir: Path) -> Dict[str, Any]:
    """Read settings.json and settings.local.json for MCP servers, hooks, permissions."""
    result: Dict[str, Any] = {
        "mcp_servers": [],
        "hooks": {},
        "permissions": {},
        "has_settings": False,
    }

    for filename in ("settings.json", "settings.local.json"):
        cfg = read_json_config(config_dir / filename)
        if cfg is None:
            continue
        result["has_settings"] = True

        # MCP servers
        for name, scfg in cfg.get("mcpServers", {}).items():
            if not isinstance(scfg, dict):
                continue
            result["mcp_servers"].append({
                "name": name,
                "command": scfg.get("command"),
                "has_args": bool(scfg.get("args")),
                "has_url": bool(scfg.get("url")),
                "source": filename,
            })

        # Hooks
        hooks = cfg.get("hooks", {})
        if hooks:
            result["hooks"].update(hooks)

        # Permissions
        perms = cfg.get("permissions", {})
        if perms:
            result["permissions"].update(perms)

    return result


def _scan_installed_plugins(config_dir: Path) -> List[Dict[str, Any]]:
    """Read ``plugins/installed_plugins.json``."""
    plugins_path = config_dir / "plugins" / "installed_plugins.json"
    cfg = read_json_config(plugins_path)
    if cfg is None:
        return []

    if isinstance(cfg, list):
        return [{"name": p.get("name", "unknown"), "enabled": p.get("enabled", True)}
                for p in cfg if isinstance(p, dict)]
    if isinstance(cfg, dict):
        plugins_list = cfg.get("plugins", [])
        if isinstance(plugins_list, list):
            return [{"name": p.get("name", "unknown"), "enabled": p.get("enabled", True)}
                    for p in plugins_list if isinstance(p, dict)]
    return []


def _scan_skills_dir(config_dir: Path) -> List[OutputSkillEntry]:
    """Scan ``~/.claude/skills/`` for SKILL.md files."""
    skills_dir = config_dir / "skills"
    if not skills_dir.is_dir():
        return []

    skills: List[OutputSkillEntry] = []
    for entry in sorted(skills_dir.iterdir()):
        if entry.is_dir():
            parsed = parse_skill_md(entry)
            if parsed:
                skills.append({
                    "name": parsed.get("name", entry.name),
                    "description": parsed.get("description", ""),
                    "emoji": None,
                    "eligible": True,
                    "disabled": False,
                    "blockedByAllowlist": False,
                    "source": "skills_dir",
                    "bundled": False,
                    "primaryEnv": None,
                    "homepage": parsed.get("homepage"),
                    "missing": _EMPTY_MISSING,
                })
    return skills


# =============================================================================
# Version Detection
# =============================================================================

def _detect_bot_version(config_dir: Path, cli_cmd: Optional[List[str]]) -> Optional[str]:
    """Detect Claude Code version from CLI or session files."""
    # Try CLI --version first
    if cli_cmd:
        try:
            result = subprocess.run(
                cli_cmd + ["--version"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                line = result.stdout.strip().splitlines()[0]
                match = re.search(r"v?\d+\.\d+(?:\.\d+)?", line)
                return match.group(0) if match else line.strip() or None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    # Fallback: check session files for version metadata
    session_files = _find_cli_session_files(config_dir)
    for sf in session_files[-3:]:  # check last few sessions
        try:
            with open(sf, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # Look for system init events with version info
                    if data.get("type") == "system" and data.get("subtype") == "init":
                        ver = data.get("version") or data.get("cli_version")
                        if ver:
                            return str(ver)
        except OSError:
            continue

    return None


# =============================================================================
# Desktop Helpers
# =============================================================================

def _extract_desktop_mcp_servers(desktop_sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract MCP server info from Desktop audit init events."""
    servers: List[Dict[str, Any]] = []
    seen: set = set()

    for sess in desktop_sessions:
        for evt in sess["audit"]:
            if evt.get("type") == "system" and evt.get("subtype") == "init":
                for srv in evt.get("mcp_servers", []):
                    name = srv.get("name", "unknown")
                    if name not in seen:
                        seen.add(name)
                        servers.append({
                            "name": name,
                            "status": srv.get("status", "unknown"),
                            "source": "desktop_audit",
                        })
    return servers


def _get_final_result(audit_events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Get the last result entry from audit events (costs are cumulative)."""
    last_result = None
    for evt in audit_events:
        if evt.get("type") == "result":
            last_result = evt
    return last_result


def _extract_desktop_models(desktop_sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract model usage and cost info from Desktop sessions."""
    models_used: set = set()
    model_costs: Dict[str, float] = defaultdict(float)

    for sess in desktop_sessions:
        model = sess["meta"].get("model", "unknown")
        models_used.add(model)
        result = _get_final_result(sess["audit"])
        if result:
            for mname, mu in result.get("modelUsage", {}).items():
                model_costs[mname] += mu.get("costUSD", 0)

    model_lines = []
    for m in sorted(models_used):
        cost = model_costs.get(m, 0)
        model_lines.append(f"{m}: ${cost:.4f}")

    return {
        "raw_output": "\n".join(model_lines) if model_lines else "No model usage data available",
        "passed": True,
    }


# =============================================================================
# Main Scan Function
# =============================================================================

def scan_cowork(
    install_info: ClawdbotInstallInfo,
    full: bool = False,
    limit: int = 50,
) -> Optional[Dict[str, Any]]:
    """Scan a cowork (Claude Desktop + Claude Code CLI) installation and produce a report.

    Parses Desktop audit sessions from ``local-agent-mode-sessions/`` and
    CLI sessions from ``~/.claude/projects/``.  Each agent's data is kept in
    a separate entry under the ``"agents"`` key; the ``"summary"`` merges both.

    Args:
        install_info: Detected install info (bot_variant, bot_config_dir, etc.)
        full: If True, include detailed sub-sections alongside summary.
        limit: Max tool_calls to include in session analysis.

    Returns:
        Report dict compatible with openclaw_usage.py, or None on failure.
    """
    config_dir = install_info.bot_config_dir
    cli_cmd = install_info.bot_cli_cmd

    # Detect version
    version = _detect_bot_version(config_dir, cli_cmd)

    # ── Desktop sessions ──
    desktop_sessions_dir = _find_desktop_sessions_dir()
    desktop_sessions: List[Dict[str, Any]] = []
    desktop_tool_events: List[Dict[str, Any]] = []
    if desktop_sessions_dir:
        desktop_sessions = _discover_desktop_sessions(desktop_sessions_dir)
        desktop_tool_events = _parse_desktop_tool_events(desktop_sessions)

    # Deduplicate by event id
    seen_ids: set = set()
    unique_events: List[Dict[str, Any]] = []
    for evt in desktop_tool_events:
        eid = evt.get("id", "")
        if eid and eid in seen_ids:
            continue
        if eid:
            seen_ids.add(eid)
        unique_events.append(evt)

    # Scrub inputs
    for evt in unique_events:
        if isinstance(evt.get("input"), dict):
            evt["input"] = scrub_arguments(evt["input"])

    # ── Classify events ──
    classified = _classify_tool_events(unique_events)

    # ── Settings and plugins from config ──
    settings = _scan_settings(config_dir)
    installed_plugins = _scan_installed_plugins(config_dir)
    skills_from_dir = _scan_skills_dir(config_dir)

    # ── Merge MCP servers from Desktop audit + settings ──
    desktop_mcp = _extract_desktop_mcp_servers(desktop_sessions) if desktop_sessions else []
    all_mcp_servers = settings["mcp_servers"] + desktop_mcp

    # Merge skills: from dir + from session events
    all_skills = skills_from_dir + classified["skills"]

    # Merge plugins: from installed_plugins.json + from session MCP + from settings MCP
    all_plugins = installed_plugins + classified["plugins"]
    # Also add settings-based MCP servers as plugins
    settings_mcp_seen = {p["name"] for p in all_plugins}
    for srv in all_mcp_servers:
        if srv["name"] not in settings_mcp_seen:
            settings_mcp_seen.add(srv["name"])
            all_plugins.append({
                "name": srv["name"],
                "source": srv.get("source", "settings"),
                "enabled": True,
            })

    # ── Models status ──
    if desktop_sessions:
        models_status = _extract_desktop_models(desktop_sessions)
    else:
        models_status = {"raw_output": "No desktop sessions found", "passed": True}

    # ── Security audit ──
    sessions_total = len(desktop_sessions)
    security_audit: Dict[str, Any] = {
        "raw_output": f"Sessions scanned: {sessions_total}",
        "passed": True,
    }

    # ── Build web activity ──
    web_activity: Dict[str, Any] = {
        "browser_urls": classified["browser_urls"],
        "fetched_urls": classified["fetched_urls"],
        "search_queries": classified["search_queries"],
        "browser_urls_count": len(classified["browser_urls"]),
        "fetched_urls_count": len(classified["fetched_urls"]),
        "search_queries_count": len(classified["search_queries"]),
    }

    # ── Permissions from settings + session-observed ──
    config_permissions = list(settings.get("permissions", {}).keys())
    session_permissions = classified["permissions"]
    all_permissions = sorted(set(config_permissions + session_permissions))

    # ── Build summary ──
    tool_counts = classified["tool_counts"]
    sorted_tools = sorted(tool_counts.keys())
    sorted_apps = classified["apps"]

    summary: OutputSummary = {
        "active_skills": all_skills,
        "active_skills_count": len(all_skills),
        "apps_detected": sorted_apps,
        "apps_detected_count": len(sorted_apps),
        "apps_call_count": classified["apps_call_count"],
        "apps_commands": classified["apps_commands"],
        "tools_used": sorted_tools,
        "tools_used_count": len(sorted_tools),
        "tools_call_count": tool_counts,
        "total_tool_calls": sum(tool_counts.values()),
        "sessions_scanned": sessions_total,
        "cron_jobs": [],
        "cron_jobs_count": 0,
        # CISO-relevant
        "security_audit": security_audit,
        "active_plugins": all_plugins,
        "active_plugins_count": len(all_plugins),
        "channels": [],
        "channels_count": 0,
        "nodes": classified["nodes"],
        "nodes_count": len(classified["nodes"]),
        "models_status": models_status,
        "autonomous_mode": False,
        "max_concurrent": 1,
        "permissions": all_permissions,
        "permissions_count": len(all_permissions),
        "web_activity": web_activity,
    }

    # ── Build result ──
    system_info = get_system_info()
    result: Dict[str, Any] = {
        "scan_timestamp": datetime.now().isoformat(),
        "bot_cli_cmd": " ".join(cli_cmd) if cli_cmd else "claude",
        "bot_variant": install_info.bot_variant,
        "bot_version": version,
        "bot_config_dir": str(config_dir),
        "system_info": system_info,
        "summary": summary,
    }

    if full:
        # Build tool_calls list for session_analysis (limit applied)
        tool_calls_list = [
            {
                "tool_name": evt["tool_name"],
                "tool_id": evt.get("id", ""),
                "timestamp": evt.get("timestamp", ""),
                "session": evt.get("session", ""),
                "arguments": evt.get("input", {}),
            }
            for evt in unique_events
        ]
        # Sort by timestamp (most recent first)
        tool_calls_list.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        tool_calls_list = tool_calls_list[:limit]

        result["active_skills"] = {
            "active_skills": all_skills,
            "count": len(all_skills),
            "total": len(all_skills),
        }
        result["session_analysis"] = {
            "tool_calls": tool_calls_list,
            "tools_summary": tool_counts,
            "apps_summary": classified["apps_call_count"],
            "apps_commands": classified["apps_commands"],
            "web_activity": web_activity,
            "total_tool_calls": sum(tool_counts.values()),
            "unique_tools": len(tool_counts),
            "unique_apps": len(sorted_apps),
            "sessions_scanned": sessions_total,
        }
        result["security_audit"] = security_audit
        result["active_plugins"] = {
            "active_plugins": all_plugins,
            "count": len(all_plugins),
            "total": len(all_plugins),
        }
        result["channels"] = {
            "channels": [],
            "count": 0,
        }
        result["nodes"] = {
            "nodes": classified["nodes"],
            "count": len(classified["nodes"]),
        }
        result["models_status"] = models_status
        result["agent_config"] = {
            "autonomous_mode": False,
            "max_concurrent": 1,
        }
        result["exec_approvals"] = {
            "approvals_path": None,
            "approvals_exist": False,
            "permissions": all_permissions,
            "permissions_count": len(all_permissions),
        }
        result["settings"] = {
            "mcp_servers": all_mcp_servers,
            "hooks": settings.get("hooks", {}),
        }

    return result
