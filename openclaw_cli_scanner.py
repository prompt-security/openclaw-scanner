#!/usr/bin/env python3
"""
OpenClaw CLI Scanner
Fetches relevant data from OpenClaw using the CLI commands.
Requires: openclaw CLI installed and configured.
"""

import json
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional


class OpenClawCLIScanner:
    """Scanner that uses OpenClaw CLI to fetch installation and integration data."""

    def __init__(self, cli_command: str = "openclaw"):
        """Initialize scanner with CLI command name.

        Args:
            cli_command: The CLI command to use (openclaw, moltbot, or clawdbot)
        """
        self.cli_command = cli_command
        self.results: Dict[str, Any] = {}

    def _run_cli(self, *args, timeout: int = 30) -> Optional[Dict[str, Any]]:
        """Run an OpenClaw CLI command and return JSON output.

        Args:
            *args: CLI command arguments
            timeout: Command timeout in seconds

        Returns:
            Parsed JSON output or None if command failed
        """
        cmd = [self.cli_command] + list(args) + ["--json"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
            return None
        except subprocess.TimeoutExpired:
            return {"error": "timeout", "command": " ".join(cmd)}
        except json.JSONDecodeError:
            return {"error": "invalid_json", "raw_output": result.stdout[:500]}
        except FileNotFoundError:
            return {"error": "cli_not_found", "command": self.cli_command}
        except Exception as e:
            return {"error": str(e)}

    def _run_cli_text(self, *args, timeout: int = 30) -> Optional[str]:
        """Run an OpenClaw CLI command and return text output.

        Args:
            *args: CLI command arguments
            timeout: Command timeout in seconds

        Returns:
            Text output or None if command failed
        """
        cmd = [self.cli_command] + list(args)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None

    def check_cli_available(self) -> Dict[str, Any]:
        """Check if OpenClaw CLI is available and get version."""
        # Try different CLI names
        cli_names = ["openclaw", "moltbot", "clawdbot"]

        for cli in cli_names:
            try:
                result = subprocess.run(
                    [cli, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    self.cli_command = cli
                    return {
                        "available": True,
                        "cli_command": cli,
                        "version": result.stdout.strip()
                    }
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        return {
            "available": False,
            "cli_command": None,
            "error": "OpenClaw CLI not found. Tried: " + ", ".join(cli_names)
        }

    def get_skills(self) -> Dict[str, Any]:
        """Get list of available skills."""
        skills_list = self._run_cli("skills", "list")
        skills_check = self._run_cli("skills", "check")

        return {
            "skills": skills_list,
            "check": skills_check
        }

    def get_channels(self) -> Dict[str, Any]:
        """Get channel configuration and status."""
        channels_list = self._run_cli("channels", "list")
        channels_status = self._run_cli("channels", "status")

        return {
            "list": channels_list,
            "status": channels_status
        }

    def get_agents(self) -> Dict[str, Any]:
        """Get list of agents."""
        return self._run_cli("agents", "list") or {}

    def get_sessions(self) -> Dict[str, Any]:
        """Get conversation sessions."""
        return self._run_cli("sessions") or {}

    def get_status(self) -> Dict[str, Any]:
        """Get overall status."""
        status = self._run_cli("status")
        health = self._run_cli("health")
        gateway_status = self._run_cli("gateway", "status")

        return {
            "status": status,
            "health": health,
            "gateway": gateway_status
        }

    def get_models(self) -> Dict[str, Any]:
        """Get model configuration."""
        models_list = self._run_cli("models", "list")
        models_status = self._run_cli("models", "status")
        aliases = self._run_cli("models", "aliases", "list")
        fallbacks = self._run_cli("models", "fallbacks", "list")

        return {
            "list": models_list,
            "status": models_status,
            "aliases": aliases,
            "fallbacks": fallbacks
        }

    def get_plugins(self) -> Dict[str, Any]:
        """Get installed plugins."""
        return self._run_cli("plugins", "list") or {}

    def get_nodes(self) -> Dict[str, Any]:
        """Get paired nodes."""
        return self._run_cli("nodes", "list") or {}

    def get_cron_jobs(self) -> Dict[str, Any]:
        """Get scheduled cron jobs."""
        return self._run_cli("cron", "list") or {}

    def get_memory_status(self) -> Dict[str, Any]:
        """Get memory/vector search status."""
        return self._run_cli("memory", "status") or {}

    def run_doctor(self) -> Dict[str, Any]:
        """Run health check diagnostics."""
        # Doctor might not support --json, try text output
        doctor_output = self._run_cli_text("doctor")
        return {
            "output": doctor_output,
            "ran": doctor_output is not None
        }

    def get_config(self, paths: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get configuration values for specified paths."""
        if paths is None:
            paths = [
                "channels",
                "skills",
                "agents",
                "gateway",
                "models",
                "tools",
                "mcpServers",
            ]

        config = {}
        for path in paths:
            result = self._run_cli("config", "get", path)
            if result and not result.get("error"):
                config[path] = result

        return config

    def scan_all(self) -> Dict[str, Any]:
        """Run all scans and collect results."""
        self.results = {
            "scan_timestamp": datetime.now().isoformat(),
            "cli_info": self.check_cli_available(),
        }

        if not self.results["cli_info"]["available"]:
            return self.results

        # Gather all data
        self.results["skills"] = self.get_skills()
        self.results["channels"] = self.get_channels()
        self.results["agents"] = self.get_agents()
        self.results["sessions"] = self.get_sessions()
        self.results["status"] = self.get_status()
        self.results["models"] = self.get_models()
        self.results["plugins"] = self.get_plugins()
        self.results["nodes"] = self.get_nodes()
        self.results["cron"] = self.get_cron_jobs()
        self.results["memory"] = self.get_memory_status()
        self.results["config"] = self.get_config()
        self.results["doctor"] = self.run_doctor()

        return self.results

    def generate_report(self) -> str:
        """Generate a human-readable report."""
        if not self.results:
            self.scan_all()

        lines = [
            "=" * 60,
            "OPENCLAW CLI SCANNER REPORT",
            f"Scan Time: {self.results.get('scan_timestamp', 'N/A')}",
            "=" * 60,
            "",
        ]

        # CLI Info
        cli_info = self.results.get("cli_info", {})
        lines.append("CLI INFORMATION:")
        if cli_info.get("available"):
            lines.append(f"  Command: {cli_info.get('cli_command')}")
            lines.append(f"  Version: {cli_info.get('version', 'N/A')}")
        else:
            lines.append(f"  ERROR: {cli_info.get('error', 'CLI not available')}")
            return "\n".join(lines)

        lines.append("")

        # Status
        status = self.results.get("status", {})
        if status.get("status") or status.get("health"):
            lines.append("-" * 40)
            lines.append("STATUS:")
            lines.append("-" * 40)
            if isinstance(status.get("status"), dict):
                for k, v in status["status"].items():
                    if not isinstance(v, (dict, list)):
                        lines.append(f"  {k}: {v}")
            if isinstance(status.get("gateway"), dict):
                lines.append("  Gateway:")
                for k, v in status["gateway"].items():
                    if not isinstance(v, (dict, list)):
                        lines.append(f"    {k}: {v}")
            lines.append("")

        # Channels
        channels = self.results.get("channels", {})
        if channels.get("list") or channels.get("status"):
            lines.append("-" * 40)
            lines.append("CHANNELS:")
            lines.append("-" * 40)
            ch_list = channels.get("list")
            if isinstance(ch_list, list):
                for ch in ch_list:
                    if isinstance(ch, dict):
                        name = ch.get("name") or ch.get("type") or "unknown"
                        status_str = ch.get("status", "")
                        lines.append(f"  - {name} [{status_str}]")
                    else:
                        lines.append(f"  - {ch}")
            elif isinstance(ch_list, dict):
                for ch_type, ch_data in ch_list.items():
                    lines.append(f"  - {ch_type}")
            lines.append("")

        # Skills
        skills = self.results.get("skills", {})
        if skills.get("skills"):
            lines.append("-" * 40)
            lines.append("SKILLS:")
            lines.append("-" * 40)
            skills_list = skills.get("skills")
            if isinstance(skills_list, list):
                ready = [s for s in skills_list if isinstance(s, dict) and s.get("ready")]
                not_ready = [s for s in skills_list if isinstance(s, dict) and not s.get("ready")]

                if ready:
                    lines.append(f"  Ready ({len(ready)}):")
                    for s in ready[:20]:
                        name = s.get("name", "unknown")
                        lines.append(f"    - {name}")
                    if len(ready) > 20:
                        lines.append(f"    ... and {len(ready) - 20} more")

                if not_ready:
                    lines.append(f"  Not Ready ({len(not_ready)}):")
                    for s in not_ready[:10]:
                        name = s.get("name", "unknown")
                        missing = s.get("missing", [])
                        missing_str = f" (missing: {', '.join(missing[:3])})" if missing else ""
                        lines.append(f"    - {name}{missing_str}")
            elif isinstance(skills_list, dict):
                for skill_name, skill_data in list(skills_list.items())[:20]:
                    lines.append(f"  - {skill_name}")
            lines.append("")

        # Agents
        agents = self.results.get("agents", {})
        if agents:
            lines.append("-" * 40)
            lines.append("AGENTS:")
            lines.append("-" * 40)
            if isinstance(agents, list):
                for agent in agents:
                    if isinstance(agent, dict):
                        name = agent.get("name") or agent.get("id") or "unknown"
                        workspace = agent.get("workspace", "")
                        lines.append(f"  - {name}")
                        if workspace:
                            lines.append(f"      workspace: {workspace}")
                    else:
                        lines.append(f"  - {agent}")
            elif isinstance(agents, dict):
                for agent_id, agent_data in agents.items():
                    lines.append(f"  - {agent_id}")
            lines.append("")

        # Models
        models = self.results.get("models", {})
        if models.get("list") or models.get("status"):
            lines.append("-" * 40)
            lines.append("MODELS:")
            lines.append("-" * 40)
            models_list = models.get("list")
            if isinstance(models_list, list):
                for model in models_list[:15]:
                    if isinstance(model, dict):
                        name = model.get("name") or model.get("id") or "unknown"
                        provider = model.get("provider", "")
                        provider_str = f" [{provider}]" if provider else ""
                        lines.append(f"  - {name}{provider_str}")
                    else:
                        lines.append(f"  - {model}")
                if len(models_list) > 15:
                    lines.append(f"  ... and {len(models_list) - 15} more")
            elif isinstance(models_list, dict):
                for model_id, model_data in list(models_list.items())[:15]:
                    lines.append(f"  - {model_id}")

            # Aliases
            aliases = models.get("aliases")
            if aliases and isinstance(aliases, dict):
                lines.append("  Aliases:")
                for alias, target in list(aliases.items())[:5]:
                    lines.append(f"    {alias} -> {target}")
            lines.append("")

        # Plugins
        plugins = self.results.get("plugins", {})
        if plugins:
            lines.append("-" * 40)
            lines.append("PLUGINS:")
            lines.append("-" * 40)
            if isinstance(plugins, list):
                for plugin in plugins:
                    if isinstance(plugin, dict):
                        name = plugin.get("name", "unknown")
                        status = plugin.get("status", "")
                        lines.append(f"  - {name} [{status}]")
                    else:
                        lines.append(f"  - {plugin}")
            elif isinstance(plugins, dict):
                for plugin_name, plugin_data in plugins.items():
                    lines.append(f"  - {plugin_name}")
            lines.append("")

        # Nodes
        nodes = self.results.get("nodes", {})
        if nodes:
            lines.append("-" * 40)
            lines.append("NODES:")
            lines.append("-" * 40)
            if isinstance(nodes, list):
                for node in nodes:
                    if isinstance(node, dict):
                        name = node.get("name") or node.get("id") or "unknown"
                        status = node.get("status", "")
                        lines.append(f"  - {name} [{status}]")
                    else:
                        lines.append(f"  - {node}")
            lines.append("")

        # Cron Jobs
        cron = self.results.get("cron", {})
        if cron:
            lines.append("-" * 40)
            lines.append("CRON JOBS:")
            lines.append("-" * 40)
            if isinstance(cron, list):
                for job in cron:
                    if isinstance(job, dict):
                        name = job.get("name") or job.get("id") or "unknown"
                        schedule = job.get("schedule", "")
                        lines.append(f"  - {name}: {schedule}")
                    else:
                        lines.append(f"  - {job}")
            lines.append("")

        # Doctor Output
        doctor = self.results.get("doctor", {})
        if doctor.get("ran") and doctor.get("output"):
            lines.append("-" * 40)
            lines.append("DOCTOR DIAGNOSTICS:")
            lines.append("-" * 40)
            # Show first 20 lines of doctor output
            doc_lines = doctor["output"].split("\n")[:20]
            for line in doc_lines:
                lines.append(f"  {line}")
            if len(doctor["output"].split("\n")) > 20:
                lines.append("  ... (truncated)")
            lines.append("")

        return "\n".join(lines)

    def export_json(self, filepath: Optional[str] = None) -> str:
        """Export results as JSON."""
        if not self.results:
            self.scan_all()

        output = json.dumps(self.results, indent=2, default=str)

        if filepath:
            with open(filepath, "w") as f:
                f.write(output)

        return output


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan OpenClaw installation using CLI commands",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Full scan with text report
  %(prog)s --json             # Full scan with JSON output
  %(prog)s --skills           # Only show skills
  %(prog)s --channels         # Only show channels
  %(prog)s --status           # Only show status
  %(prog)s -o report.json     # Save JSON to file
        """
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Save output to file"
    )
    parser.add_argument(
        "--cli",
        type=str,
        default="openclaw",
        help="CLI command to use (openclaw, moltbot, clawdbot)"
    )
    parser.add_argument(
        "--skills",
        action="store_true",
        help="Only show skills"
    )
    parser.add_argument(
        "--channels",
        action="store_true",
        help="Only show channels"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Only show status"
    )
    parser.add_argument(
        "--models",
        action="store_true",
        help="Only show models"
    )
    parser.add_argument(
        "--agents",
        action="store_true",
        help="Only show agents"
    )
    parser.add_argument(
        "--plugins",
        action="store_true",
        help="Only show plugins"
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Run doctor diagnostics"
    )

    args = parser.parse_args()

    scanner = OpenClawCLIScanner(cli_command=args.cli)

    # Check if specific scan requested
    specific_scan = any([
        args.skills, args.channels, args.status,
        args.models, args.agents, args.plugins, args.doctor
    ])

    if specific_scan:
        # Check CLI availability first
        cli_info = scanner.check_cli_available()
        if not cli_info["available"]:
            print(f"Error: {cli_info.get('error')}")
            sys.exit(1)

        results = {"cli_info": cli_info}

        if args.skills:
            results["skills"] = scanner.get_skills()
        if args.channels:
            results["channels"] = scanner.get_channels()
        if args.status:
            results["status"] = scanner.get_status()
        if args.models:
            results["models"] = scanner.get_models()
        if args.agents:
            results["agents"] = scanner.get_agents()
        if args.plugins:
            results["plugins"] = scanner.get_plugins()
        if args.doctor:
            results["doctor"] = scanner.run_doctor()

        scanner.results = results
    else:
        # Full scan
        scanner.scan_all()

    # Output
    if args.json:
        output = scanner.export_json(args.output)
        if not args.output:
            print(output)
    else:
        report = scanner.generate_report()
        print(report)
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)
            print(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    main()
