"""Shared data structures for openclaw-scanner.

All TypedDicts used across installation_tracker.py and platform_compat/.
"""

from typing import Any, Dict, List, Optional, TypedDict

# CLI command as list of string parts (ex. ["/usr/bin/openclaw"] or ["npx", "openclaw"])
CliCommand = List[str]


# =============================================================================
# Platform Compat Structures (used by platform_compat/)
# =============================================================================

class UserInfo(TypedDict):
    """User information returned by get_user_info()."""
    username: str                    # e.g. "john"
    home_directory: str              # e.g. "/Users/john"
    user_id: Optional[str]           # Unix: "501", Windows: None
    group_id: Optional[str]          # Unix: "20", Windows: None
    full_name: Optional[str]         # e.g. "John Doe" or None
    shell: str                       # e.g. "/bin/zsh" or "cmd.exe"
    groups: List[str]                # e.g. ["staff", "admin"], never None
    system_info: Optional[str]       # uname output or equivalent
    computer_name: Optional[str]     # hostname or friendly name
    local_hostname: Optional[str]    # macOS only, others: None


class OsInfo(TypedDict):
    """Operating system information."""
    system: str      # e.g. "Darwin", "Linux", "Windows"
    release: str     # e.g. "24.6.0"
    version: str     # full version string
    machine: str     # e.g. "arm64", "x86_64"


class SystemInfo(TypedDict):
    """System information for the host being scanned (used by openclaw_usage.py)."""
    username: str       # e.g. "john"
    home_dir: str       # e.g. "/Users/john"
    current_dir: str    # current working directory
    hostname: str       # machine hostname
    os: OsInfo          # nested OS details
    shell: str          # e.g. "/bin/zsh"
    lang: str           # e.g. "en_US.UTF-8"


class ProcessInfo(TypedDict):
    """Process info returned by find_processes()."""
    user: str           # process owner, "" if unavailable
    pid: str            # process ID as string
    cpu: str            # CPU %, "" if unavailable (Windows)
    mem: str            # memory %, "" if unavailable (Windows)
    command: str        # full command line
    process_name: str   # the filter that matched (from input list)


class ToolPaths(TypedDict):
    """Tool paths returned by get_tool_paths()."""
    config: List[str]   # paths to check for config files
    logs: List[str]     # paths/globs for log files


# =============================================================================
# Tool Configuration
# =============================================================================

class ToolConfig(TypedDict, total=False):
    """Configuration for a tool to scan."""
    config_paths: List[str]
    log_paths: List[str]
    workspace_path: str
    process_names: List[str]
    default_port: Optional[int]
    binary_names: List[str]
    macos_log_subsystem: str


# =============================================================================
# Discovered Data Structures
# =============================================================================

class ApiKeyInfo(TypedDict):
    """Information about a discovered API key."""
    path: str
    value_masked: str
    length: int


class Integration(TypedDict, total=False):
    """An integration/channel/service connection."""
    name: str
    type: str
    source: str
    enabled: bool
    config: Dict[str, Any]  # Free-form config, varies per integration
    description: str
    details: Dict[str, Any]  # Free-form details


class SkillInfo(TypedDict, total=False):
    """Information about a skill/extension/plugin."""
    name: str
    type: str
    path: str
    has_manifest: bool
    has_skill_md: bool
    files: List[str]
    description: Optional[str]
    homepage: Optional[str]
    emoji: Optional[str]
    requires: List[str]
    install_methods: List[str]
    connected_services: List[str]
    enabled: bool
    has_api_key: bool
    has_env: bool
    has_config: bool
    source: str


class ServiceStats(TypedDict, total=False):
    """Statistics for an accessed service."""
    resource: str
    service_name: Optional[str]
    category: str
    access_count: int
    success_count: int
    failure_count: int
    first_seen: Optional[str]
    last_seen: Optional[str]
    access_types: List[str]


class AccessedApp(TypedDict, total=False):
    """An accessed app/service event."""
    resource: str
    access_type: str
    status: str
    service_name: Optional[str]
    service_category: str
    timestamp: Optional[str]
    line_number: int
    log_file: str
    line_sample: str


class ConfigFile(TypedDict):
    """A configuration file and its parsed data."""
    path: str
    data: Dict[str, Any]  # Config structure varies per tool


# =============================================================================
# Aggregate/Summary Structures
# =============================================================================

class AccessedAppsSummary(TypedDict):
    """Summary of accessed apps/services."""
    total_access_events: int
    by_category: Dict[str, List[ServiceStats]]
    by_status: Dict[str, int]
    unique_services: List[ServiceStats]
    access_timeline: List[Dict[str, Any]]  # Timeline events, variable structure


class WorkspaceLibrary(TypedDict, total=False):
    """Connected apps and integrations from workspace."""
    connected_apps: List[Integration]
    channels: List[Integration]
    skills: List[SkillInfo]
    skills_from_config: List[SkillInfo]
    extensions: List[SkillInfo]
    plugins: List[SkillInfo]
    mcp_servers: List[Integration]
    oauth_credentials: List[Dict[str, Any]]  # Varies per provider
    tools_md_integrations: List[Integration]


# =============================================================================
# Scan Results
# =============================================================================

class ScanResult(TypedDict, total=False):
    """Result of scanning a single tool."""
    tool_name: str
    installed: bool
    installation_details: Dict[str, Any]  # Varies: binary_path, npm, workspace_exists
    active: bool
    processes: List[ProcessInfo]
    port_listening: bool
    default_port: Optional[int]
    config_files: List[ConfigFile]
    log_files: List[str]
    log_sources: List[str]
    connections: List[Dict[str, Any]]  # Connection info from log parsing
    api_keys_found: List[ApiKeyInfo]
    accessed_apps: List[AccessedApp]
    accessed_apps_summary: AccessedAppsSummary
    integrations: List[Integration]
    skills: List[SkillInfo]
    workspace_library: WorkspaceLibrary
