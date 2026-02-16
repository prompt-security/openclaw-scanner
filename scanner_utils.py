"""Shared utilities for scanning OpenClaw variants (nanobot, picoclaw).

Provides helpers reusable across all variant scanners:
- camel_to_snake: normalize camelCase config keys to snake_case
- parse_skill_md: parse SKILL.md files with YAML frontmatter
- mask_api_key: redact API keys for safe reporting
- aggregate_tool_calls: build summaries from raw tool_call lists
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import json5
import yaml

from scrubber import scrub_url


# =============================================================================
# Key Casing Normalization
# =============================================================================

def _camel_to_snake_key(key: str) -> str:
    """Convert a single camelCase key to snake_case.

    Examples:
        maxTokens -> max_tokens
        apiKey -> api_key
        mcpServers -> mcp_servers
        botToken -> bot_token
    """
    # Insert underscore before uppercase letters, then lowercase
    s1 = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', key)
    return re.sub(r'([a-z\d])([A-Z])', r'\1_\2', s1).lower()


def camel_to_snake(obj: Any) -> Any:
    """Recursively convert all dict keys from camelCase to snake_case.

    Leaves values untouched. Handles nested dicts and lists.
    Used to normalize nanobot config (camelCase) to match picoclaw (snake_case).

    Verified mapping (from picoclaw's own migrate command):
        maxTokens         -> max_tokens
        apiKey            -> api_key
        apiBase           -> api_base
        mcpServers        -> mcp_servers
        botToken          -> bot_token
        allowFrom         -> allow_from
        restrictToWorkspace -> restrict_to_workspace
        maxToolIterations -> max_tool_iterations
        memoryWindow      -> memory_window
    """
    if isinstance(obj, dict):
        return {_camel_to_snake_key(k): camel_to_snake(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [camel_to_snake(item) for item in obj]
    return obj


# =============================================================================
# SKILL.md Parsing
# =============================================================================

def parse_skill_md(skill_dir: Path) -> Optional[Dict[str, Any]]:
    """Parse a SKILL.md file with YAML frontmatter.

    Expected format:
        ---
        name: skill-name
        description: What the skill does.
        homepage: https://example.com
        metadata: {"nanobot": {"emoji": "🐙", "requires": {"bins": ["gh"]}}}
        ---
        # Skill Title
        Markdown instructions...

    Args:
        skill_dir: Directory containing SKILL.md

    Returns:
        Dict with parsed frontmatter fields, or None if no valid SKILL.md found.
        Always includes 'path' key with the directory path.
    """
    skill_file = skill_dir / "SKILL.md"
    if not skill_file.exists():
        return None

    try:
        content = skill_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    # Extract YAML frontmatter between --- markers
    if not content.startswith("---"):
        return {"name": skill_dir.name, "path": str(skill_dir), "raw": True}

    parts = content.split("---", 2)
    if len(parts) < 3:
        return {"name": skill_dir.name, "path": str(skill_dir), "raw": True}

    frontmatter_text = parts[1]

    try:
        parsed = yaml.safe_load(frontmatter_text)
    except yaml.YAMLError:
        return {"name": skill_dir.name, "path": str(skill_dir), "raw": True}

    if not isinstance(parsed, dict):
        return {"name": skill_dir.name, "path": str(skill_dir), "raw": True}

    result: Dict[str, Any] = {"path": str(skill_dir)}
    result.update(parsed)

    # Ensure name is always present
    if "name" not in result:
        result["name"] = skill_dir.name

    return result


# =============================================================================
# API Key Masking
# =============================================================================

def mask_api_key(key: str) -> str:
    """Mask an API key for safe reporting: show first 4 + last 2 chars.

    Examples:
        sk-ant-api03-xxxx...yyyy -> sk-a****yy
        short -> ****
    """
    if not key or len(key) <= 8:
        return "****"
    return key[:4] + "****" + key[-2:]


def has_api_key(provider_config: Dict[str, Any]) -> bool:
    """Check if a provider config has a non-empty API key.

    Works with both camelCase (apiKey) and snake_case (api_key) configs.
    """
    key = provider_config.get("api_key") or provider_config.get("apiKey") or ""
    return bool(key.strip())


# =============================================================================
# Config File Reading
# =============================================================================

def read_json_config(path: Path) -> Optional[Dict[str, Any]]:
    """Read and parse a JSON config file.

    Handles:
    - Standard JSON (nanobot, picoclaw)
    - JSON5 / JSONC with comments and trailing commas (OpenClaw)

    Uses stdlib json.loads() first (fast, strict), then falls back to
    json5.loads() for files that contain comments or trailing commas.

    Returns None if file doesn't exist or can't be parsed.
    """
    if not path.exists():
        return None

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    # Try strict JSON first (handles nanobot + picoclaw)
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Fall back to json5 for files with comments / trailing commas (OpenClaw)
    try:
        return json5.loads(content)
    except ValueError:
        return None


# =============================================================================
# Tool Call Aggregation (shared by nano_scanner + openclaw_usage)
# =============================================================================

def aggregate_tool_calls(tool_calls: List[Dict[str, Any]], sessions_scanned: int) -> Dict[str, Any]:
    """Build summaries, web activity, and return dict from raw tool_call list.

    Both nano_scanner._scan_session_logs() and openclaw_usage.scan_session_logs()
    collect a list of tool_call dicts, then need identical post-processing.
    This function is that shared tail.

    Args:
        tool_calls: List of dicts with tool_name, arguments, apps_detected,
                    timestamp, session, tool_id.
        sessions_scanned: Number of session files that were parsed.

    Returns:
        Dict with tool_calls, tools_summary, apps_summary, apps_commands,
        web_activity, total_tool_calls, unique_tools, unique_apps,
        sessions_scanned.
    """
    # Sort by timestamp (most recent first)
    tool_calls.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    # Build tools usage summary
    tools_summary: Dict[str, int] = {}
    for tc in tool_calls:
        tname = tc.get("tool_name", "unknown")
        tools_summary[tname] = tools_summary.get(tname, 0) + 1
    tools_summary = dict(sorted(tools_summary.items(), key=lambda x: x[1], reverse=True))

    # Build apps usage summary and collect full commands per app
    apps_summary: Dict[str, int] = {}
    apps_commands: Dict[str, List[Dict[str, str]]] = {}
    for tc in tool_calls:
        tc_args = tc.get("arguments", {})
        command = tc_args.get("command", "") if isinstance(tc_args, dict) else ""
        timestamp = tc.get("timestamp", "")
        for app in tc.get("apps_detected", []):
            apps_summary[app] = apps_summary.get(app, 0) + 1
            if command:
                if app not in apps_commands:
                    apps_commands[app] = []
                apps_commands[app].append({
                    "command": command,
                    "timestamp": timestamp,
                    "session": tc.get("session", ""),
                })
    apps_summary = dict(sorted(apps_summary.items(), key=lambda x: x[1], reverse=True))
    apps_commands = {app: apps_commands[app] for app in apps_summary if app in apps_commands}

    # Extract web activity from tool calls
    browser_urls: List[Dict[str, str]] = []
    fetched_urls: List[Dict[str, str]] = []
    search_queries: List[Dict[str, str]] = []

    for tc in tool_calls:
        tool_name = tc.get("tool_name", "")
        tc_args = tc.get("arguments", {})
        if not isinstance(tc_args, dict):
            continue
        tc_ts = tc.get("timestamp", "")
        tc_session = tc.get("session", "")

        if tool_name == "browser":
            url = tc_args.get("targetUrl", "") or tc_args.get("url", "")
            if url:
                browser_urls.append({
                    "url": scrub_url(url),
                    "action": tc_args.get("action", "open"),
                    "timestamp": tc_ts,
                    "session": tc_session,
                })
        elif tool_name == "web_fetch":
            url = tc_args.get("url", "")
            if url:
                fetched_urls.append({
                    "url": scrub_url(url),
                    "timestamp": tc_ts,
                    "session": tc_session,
                })
        elif tool_name == "web_search":
            query = tc_args.get("query", "")
            if query:
                search_queries.append({
                    "query": query,
                    "timestamp": tc_ts,
                    "session": tc_session,
                })

    web_activity: Dict[str, Any] = {
        "browser_urls": browser_urls,
        "fetched_urls": fetched_urls,
        "search_queries": search_queries,
        "browser_urls_count": len(browser_urls),
        "fetched_urls_count": len(fetched_urls),
        "search_queries_count": len(search_queries),
    }

    return {
        "tool_calls": tool_calls,
        "tools_summary": tools_summary,
        "apps_summary": apps_summary,
        "apps_commands": apps_commands,
        "web_activity": web_activity,
        "total_tool_calls": len(tool_calls),
        "unique_tools": len(tools_summary),
        "unique_apps": len(apps_summary),
        "sessions_scanned": sessions_scanned,
    }
