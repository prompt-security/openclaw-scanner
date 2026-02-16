"""Output data structures — typed contracts for scanner output.

These TypedDicts define the exact JSON shape that the consumer expects.
Both scan_openclaw() and scan_nano() must produce data conforming to these
types.
"""

from typing import Any, Dict, List, NotRequired, Optional, TypedDict


# =============================================================================
# Skill entry — shape of each item in summary["active_skills"]
# =============================================================================

class OutputMissingRequirements(TypedDict):
    """Requirements that are NOT satisfied for a skill."""

    bins: List[str]
    anyBins: List[str]
    env: List[str]
    config: List[str]
    os: List[str]


class OutputSkillEntry(TypedDict):
    """One skill in summary.active_skills[].

    Matches the per-skill object returned by ``openclaw skills list --json``.
    Every scanner must produce this exact shape; the backend depends on it.
    """

    name: str
    description: str
    emoji: Optional[str]
    eligible: bool
    disabled: bool
    blockedByAllowlist: bool
    source: str                          # "openclaw-bundled", "workspace", "managed", "builtin", …
    bundled: bool
    primaryEnv: Optional[str]
    homepage: Optional[str]
    missing: OutputMissingRequirements


# =============================================================================
# Summary — the ``summary`` section of the scan report
# =============================================================================

_EMPTY_MISSING: OutputMissingRequirements = {
    "bins": [],
    "anyBins": [],
    "env": [],
    "config": [],
    "os": [],
}
"""Convenience constant for skills with no missing requirements."""


class OutputSummary(TypedDict):
    """Shape of result["summary"] — the section the backend consumes.

    Fields present in every scan (both openclaw and nano strategies):
    """

    # -- Skills ---------------------------------------------------------------
    active_skills: List[OutputSkillEntry]
    active_skills_count: int

    # -- Apps/tools from session-log analysis ---------------------------------
    apps_detected: List[str]
    apps_detected_count: int
    apps_call_count: Dict[str, Any]
    apps_commands: Dict[str, Any]
    tools_used: List[str]
    tools_used_count: int
    tools_call_count: Dict[str, Any]
    total_tool_calls: int
    sessions_scanned: int

    # -- Cron -----------------------------------------------------------------
    cron_jobs: List[Dict[str, Any]]
    cron_jobs_count: int

    # -- CISO-relevant --------------------------------------------------------
    security_audit: Dict[str, Any]
    active_plugins: List[Dict[str, Any]]
    active_plugins_count: int
    channels: List[Dict[str, Any]]
    channels_count: int
    nodes: List[Dict[str, Any]]
    nodes_count: int
    models_status: Dict[str, Any]

    # -- Agent config ---------------------------------------------------------
    autonomous_mode: Optional[bool]
    max_concurrent: Optional[int]

    # -- Permissions ----------------------------------------------------------
    permissions: List[Dict[str, Any]]
    permissions_count: int

    # -- Web activity ---------------------------------------------------------
    web_activity: Dict[str, Any]

    # -- Variant-specific (nano/picoclaw only) --------------------------------
    variant_providers: NotRequired[Dict[str, Any]]
    variant_mcp_servers: NotRequired[List[Dict[str, Any]]]
    variant_agent_defaults: NotRequired[Dict[str, Any]]
    variant_gateway: NotRequired[Dict[str, Any]]
