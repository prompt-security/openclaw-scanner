"""Shared scanner for OpenClaw variant tools (nanobot, picoclaw).

Both variants share ~90% identical structure, differing mainly in:
  - Key casing: nanobot=camelCase, picoclaw=snake_case
  - A few directory paths (sessions, cron, skill tiers)

This scanner produces output compatible with the existing openclaw scanner report
schema, so the backend receives the same JSON shape regardless of which variant
was detected.
"""

import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from platform_compat.common import get_system_info
from structures import ClawdbotInstallInfo
from scanner_utils import camel_to_snake, has_api_key, mask_api_key, parse_skill_md, read_json_config
from output_structures import OutputSkillEntry, OutputSummary, _EMPTY_MISSING


# =============================================================================
# Variant Definitions (data-driven, not code-branched)
# =============================================================================

NANO_VARIANT_DEFS: Dict[str, Dict[str, Any]] = {
    "nanobot": {
        "home": "~/.nanobot",
        "config_file": "config.json",
        "key_casing": "camel",           # needs camel_to_snake() normalization
        "workspace_subdir": "workspace",
        "sessions_path": "sessions",      # relative to home (NOT workspace)
        "cron_path": "cron/jobs.json",    # relative to home
        "skill_dirs": ["workspace/skills"],  # relative to home
        "log_file": "logs/nanobot.log",
        "binary": "nanobot",
        "process_patterns": ["nanobot gateway", "nanobot agent", "python.*nanobot"],
        "port": 18790,
        "pip_package": "nanobot-ai",
    },
    "picoclaw": {
        "home": "~/.picoclaw",
        "config_file": "config.json",
        "key_casing": "snake",            # already snake_case, no normalization needed
        "workspace_subdir": "workspace",
        "sessions_path": "workspace/sessions",  # relative to home
        "cron_path": "workspace/cron/jobs.json", # relative to home
        "skill_dirs": ["workspace/skills", "skills"],  # 2 tiers: workspace + global
        "log_file": None,                 # JSON structured log, path TBD
        "binary": "picoclaw",
        "process_patterns": ["picoclaw gateway", "picoclaw agent"],
        "port": 18790,
        "pip_package": None,              # Go binary, not pip
    },
}

# =============================================================================
# Config Reading & Normalization
# =============================================================================

def _read_variant_config(name: str, home: Path) -> Optional[Dict[str, Any]]:
    """Read and normalize variant config to snake_case.

    After this function, nanobot and picoclaw configs have identical key names.
    """
    vdef = NANO_VARIANT_DEFS[name]
    config_path = home / vdef["config_file"]
    cfg = read_json_config(config_path)
    if cfg is None:
        return None

    # Normalize camelCase -> snake_case for nanobot
    if vdef["key_casing"] == "camel":
        cfg = camel_to_snake(cfg)

    return cfg


# =============================================================================
# Data Extraction (from normalized config — identical for both variants)
# =============================================================================

def _extract_providers(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Extract provider info from config. Returns dict of provider_name -> info."""
    providers = cfg.get("providers", {})
    result = {}
    for name, pcfg in providers.items():
        if not isinstance(pcfg, dict):
            continue
        result[name] = {
            "has_api_key": has_api_key(pcfg),
            "api_key_masked": mask_api_key(pcfg.get("api_key", "")) if has_api_key(pcfg) else None,
            "has_api_base": bool(pcfg.get("api_base")),
        }
    return result


def _extract_channels(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Extract channel info from config. Returns dict of channel_name -> info."""
    channels = cfg.get("channels", {})
    result = {}
    for name, ccfg in channels.items():
        if not isinstance(ccfg, dict):
            continue
        result[name] = {
            "enabled": ccfg.get("enabled", False),
        }
    return result


def _extract_agent_defaults(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Extract agent defaults (model, workspace, etc.)."""
    agents = cfg.get("agents", {})
    defaults = agents.get("defaults", {})
    return {
        "model": defaults.get("model"),
        "max_tokens": defaults.get("max_tokens"),
        "temperature": defaults.get("temperature"),
        "max_tool_iterations": defaults.get("max_tool_iterations"),
        "workspace": defaults.get("workspace"),
        "restrict_to_workspace": defaults.get("restrict_to_workspace"),
    }


def _extract_mcp_servers(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract MCP server configurations from tools section."""
    tools = cfg.get("tools", {})
    mcp_servers = tools.get("mcp_servers", {})
    result = []
    for name, scfg in mcp_servers.items():
        if not isinstance(scfg, dict):
            continue
        result.append({
            "name": name,
            "command": scfg.get("command"),
            "has_url": bool(scfg.get("url")),
            "has_args": bool(scfg.get("args")),
        })
    return result


def _extract_gateway(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Extract gateway configuration."""
    gw = cfg.get("gateway", {})
    return {
        "host": gw.get("host"),
        "port": gw.get("port"),
    }


def _normalize_skill(parsed: Dict[str, Any], skill_rel_dir: str) -> OutputSkillEntry:
    """Normalize raw parse_skill_md output to the backend-expected shape."""
    # Extract variant-specific metadata (nanobot or picoclaw nested dict)
    raw_meta = parsed.get("metadata", {})
    meta: Dict[str, Any] = {}
    if isinstance(raw_meta, dict):
        # Try both variant keys; at most one will exist
        nested = raw_meta.get("nanobot", raw_meta.get("picoclaw"))
        if isinstance(nested, dict):
            meta = nested

    # Map relative skill dir to a source label ("workspace", "builtin", etc.)
    is_workspace = "workspace" in skill_rel_dir
    source = "workspace" if is_workspace else "builtin"

    return {
        "name": parsed.get("name", ""),
        "description": parsed.get("description", ""),
        "emoji": meta.get("emoji") if isinstance(meta, dict) else None,
        "eligible": True,               # present on disk → eligible
        "disabled": False,              # no disable mechanism for file-scanned skills
        "blockedByAllowlist": False,
        "source": source,
        "bundled": source == "builtin",
        "primaryEnv": meta.get("primaryEnv") if isinstance(meta, dict) else None,
        "homepage": parsed.get("homepage"),
        "missing": _EMPTY_MISSING,
    }


def _scan_skills(home: Path, vdef: Dict[str, Any]) -> List[OutputSkillEntry]:
    """Scan SKILL.md files from variant's skill directories.

    Returns skills normalized to OutputSkillEntry shape (backend contract).
    """
    skills: List[OutputSkillEntry] = []
    for skill_rel_dir in vdef["skill_dirs"]:
        skill_base = home / skill_rel_dir
        if not skill_base.is_dir():
            continue
        for entry in sorted(skill_base.iterdir()):
            if entry.is_dir():
                parsed = parse_skill_md(entry)
                if parsed:
                    skills.append(_normalize_skill(parsed, skill_rel_dir))
    return skills


def _read_cron_jobs(home: Path, vdef: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Read cron jobs from jobs.json."""
    cron_path = home / vdef["cron_path"]
    if not cron_path.exists():
        return []

    cfg = read_json_config(cron_path)
    if cfg is None:
        return []

    # Both variants store jobs under a "jobs" key
    jobs = cfg.get("jobs", [])
    if not isinstance(jobs, list):
        return []

    # Normalize job entries (nanobot uses camelCase too)
    if vdef["key_casing"] == "camel":
        jobs = [camel_to_snake(j) for j in jobs]

    return jobs


def _detect_binary(vdef: Dict[str, Any]) -> Optional[str]:
    """Find binary in PATH. Returns path string or None."""
    return shutil.which(vdef["binary"])


# =============================================================================
# Main Scan Function
# =============================================================================

def scan_nano(install_info: ClawdbotInstallInfo, full: bool = False, limit: int = 50) -> Optional[Dict[str, Any]]:  # pylint: disable=unused-argument
    """Scan a variant and produce a report compatible with openclaw scanner output.

    This is the main entry point for variant scanning. It:
    1. Reads + normalizes config
    2. Extracts providers, channels, skills, cron, MCP servers
    3. Returns a dict compatible with (matching) the openclaw scanner's output shape

    Args:
        install_info: Detected install info (bot_variant, bot_config_dir, etc.)
        full: If True, include detailed sub-sections alongside summary.
        limit: Max tool_calls to include in session analysis (TBD: future use).

    Returns:
        Report dict compatible with openclaw_usage.py, or None if variant unknown.
    """
    name = install_info.bot_variant
    home = install_info.bot_config_dir

    vdef = NANO_VARIANT_DEFS.get(name)
    if not vdef:
        return None

    # Read and normalize config
    cfg = _read_variant_config(name, home)

    # Binary detection — prefer already-resolved path from install_info
    binary_path = install_info.bot_cli_cmd[0] if install_info.bot_cli_cmd else _detect_binary(vdef)
    version = _get_version(binary_path)

    # Extract data from config (if config exists)
    providers = _extract_providers(cfg) if cfg else {}
    channels = _extract_channels(cfg) if cfg else {}
    agent_defaults = _extract_agent_defaults(cfg) if cfg else {}
    mcp_servers = _extract_mcp_servers(cfg) if cfg else []
    gateway = _extract_gateway(cfg) if cfg else {}

    # Scan filesystem
    skills = _scan_skills(home, vdef)
    cron_jobs = _read_cron_jobs(home, vdef)

    # Build report in the same shape as openclaw_usage.py main() produces
    # This ensures backend compatibility
    system_info = get_system_info()

    # Build summary matching existing schema
    channels_list = [
        {"name": ch_name, "enabled": ch_info.get("enabled", False)}
        for ch_name, ch_info in channels.items()
    ]

    # MCP servers are the plugin equivalent in nano/picoclaw
    active_plugins_list = [
        {"name": s["name"], "source": "mcp", "enabled": True}
        for s in mcp_servers
    ]

    # Security posture — restrict_to_workspace lives in agents.defaults
    tools_cfg = cfg.get("tools", {}) if cfg else {}
    agents_defaults = cfg.get("agents", {}).get("defaults", {}) if cfg else {}
    security_audit: Dict[str, Any] = {
        "restrict_to_workspace": agents_defaults.get("restrict_to_workspace", False),
        "exec_timeout": tools_cfg.get("exec", {}).get("timeout", 60),
        "channels_with_allowlist": [
            ch_name for ch_name, ch_info in channels.items()
            if ch_info.get("allow_from")
        ],
        "passed": True,
    }

    # Models status — which providers have API keys configured
    models_status: Dict[str, Any] = {
        "models_status": {
            pname: {"has_auth": pinfo.get("has_api_key", False)}
            for pname, pinfo in providers.items()
        },
        "has_auth": any(
            pinfo.get("has_api_key", False) for pinfo in providers.values()
        ),
    }

    # Empty but structurally valid web activity
    web_activity: Dict[str, Any] = {
        "browser_urls": [],
        "fetched_urls": [],
        "search_queries": [],
        "browser_urls_count": 0,
        "fetched_urls_count": 0,
        "search_queries_count": 0,
    }

    summary: OutputSummary = {
        "active_skills": skills,
        "active_skills_count": len(skills),
        "apps_detected": [],
        "apps_detected_count": 0,
        "apps_call_count": {},
        "apps_commands": {},
        "tools_used": [],
        "tools_used_count": 0,
        "tools_call_count": {},
        "total_tool_calls": 0,
        "sessions_scanned": 0,
        "cron_jobs": cron_jobs,
        "cron_jobs_count": len(cron_jobs),
        # CISO-relevant
        "security_audit": security_audit,
        "active_plugins": active_plugins_list,
        "active_plugins_count": len(active_plugins_list),
        "channels": channels_list,
        "channels_count": len(channels_list),
        "nodes": [],
        "nodes_count": 0,
        "models_status": models_status,
        "autonomous_mode": agent_defaults.get("max_tool_iterations", 0) > 0,
        "max_concurrent": 1,
        "permissions": [],
        "permissions_count": 0,
        "web_activity": web_activity,
        # Variant-specific additions
        "variant_providers": providers,
        "variant_mcp_servers": mcp_servers,
        "variant_agent_defaults": agent_defaults,
        "variant_gateway": gateway,
    }

    result: Dict[str, Any] = {
        "scan_timestamp": datetime.now().isoformat(),
        "bot_cli_cmd": binary_path or name,
        "bot_variant": name,
        "bot_version": version,
        "bot_config_dir": str(home),
        "system_info": system_info,
        "summary": summary,
    }

    if full:
        result["active_skills"] = {
            "active_skills": skills,
            "count": len(skills),
            "total": len(skills),
        }
        result["session_analysis"] = {  # no data — no session log parsing yet
            "tool_calls": [],
            "tools_summary": {},
            "apps_summary": {},
            "apps_commands": {},
            "web_activity": web_activity,
            "total_tool_calls": 0,
            "unique_tools": 0,
            "unique_apps": 0,
            "sessions_scanned": 0,
        }
        result["cron_jobs"] = {
            "cron_jobs": cron_jobs,
            "count": len(cron_jobs),
        }
        result["security_audit"] = security_audit  # partial — from config, no CLI audit
        result["active_plugins"] = {  # MCP servers mapped as plugins
            "active_plugins": active_plugins_list,
            "count": len(active_plugins_list),
            "total": len(active_plugins_list),
        }
        result["channels"] = {
            "channels": channels_list,
            "count": len(channels_list),
        }
        result["nodes"] = {  # no data — no remote nodes concept
            "nodes": [],
            "count": 0,
        }
        result["models_status"] = models_status  # from config providers
        result["agent_config"] = {
            "autonomous_mode": agent_defaults.get("max_tool_iterations", 0) > 0,
            "max_concurrent": 1,  # no data — single-process, always 1
            "agent_defaults": agent_defaults,
        }
        result["exec_approvals"] = {  # no data — no approvals system
            "approvals_path": None,
            "approvals_exist": False,
            "permissions": [],
            "permissions_count": 0,
        }

    return result


def _get_version(binary_path: Optional[str]) -> Optional[str]:
    """Try to get variant version. Best-effort, returns None on failure.

    Extracts a semver-like version (e.g. ``1.2.3``, ``v0.1.0``) from
    wherever it appears in the ``--version`` output, ignoring any emoji,
    binary-name, or other prefix/suffix decoration.
    """
    if not binary_path:
        return None

    try:
        result = subprocess.run(
            [binary_path, "--version"],
            capture_output=True, text=True, timeout=5,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            line = result.stdout.strip().splitlines()[0]
            match = re.search(r"v?\d+\.\d+(?:\.\d+)?", line)
            return match.group(0) if match else line.strip() or None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None
