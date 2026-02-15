"""Shared utilities for scanning OpenClaw variants (nanobot, picoclaw).

Provides helpers reusable across all variant scanners:
- camel_to_snake: normalize camelCase config keys to snake_case
- parse_skill_md: parse SKILL.md files with YAML frontmatter
- mask_api_key: redact API keys for safe reporting
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

import json5
import yaml


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
