"""
Platform Compatibility Layer.

Usage: from platform_compat import compat
"""

import platform

from .base import PlatformCompat

__all__ = ["compat", "PlatformCompat"]


def _create_compat() -> PlatformCompat:
    """Create platform-specific implementation. Called once at import."""
    system = platform.system()
    if system == "Darwin":
        from .darwin import DarwinCompat
        return DarwinCompat()
    elif system == "Linux":
        from .linux import LinuxCompat
        return LinuxCompat()
    else:
        raise NotImplementedError(
            f"Unsupported platform: {system}. "
            f"Supported: Darwin (macOS), Linux (including WSL2)."
        )


# Singleton - created at import, fails fast if unsupported
compat = _create_compat()
