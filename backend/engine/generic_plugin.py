import re
import subprocess
import shlex
import urllib.parse
from typing import Any, Dict, List, Optional
from engine.plugin_base import SecurityToolPlugin


def sanitize_target(target: str) -> str:
    """
    Strips URL scheme, trailing slashes, and port from a target string
    so bare domain tools (sublist3r, amass, etc.) always receive a clean FQDN/IP.
    e.g.  https://example.com/path  →  example.com
          http://192.168.1.1:8080   →  192.168.1.1
    """
    target = target.strip()
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        target = parsed.hostname or parsed.netloc or parsed.path
    # Strip trailing slash and path
    target = target.split("/")[0]
    # Strip port if present (and it's a domain, not a CIDR)
    if ":" in target and "/" not in target and not target.startswith("["):
        target = target.split(":")[0]
    return target.strip()


class ArgValidationError(ValueError):
    """Raised when AI-supplied args fail schema validation."""
    pass


class GenericBinaryPlugin(SecurityToolPlugin):
    """
    Schema-driven plugin that wraps any CLI security tool.

    Supports two modes:
    1. Legacy: simple {target} template substitution (backward compat).
    2. Schema: AI supplies args → validated → stitched into base_command.
    """

    def __init__(self, name: str, command_template: str,
                 base_command: Optional[str] = None,
                 parameters: Optional[Dict] = None,
                 description: str = ""):
        self._name = name
        self.command_template = command_template   # legacy fallback
        self.base_command = base_command           # schema-driven template
        self.parameters: Dict = parameters or {}   # schema dict from YAML
        self.description = description

    # ── Identity ──────────────────────────────────────────────────────────────

    @property
    def tool_name(self) -> str:
        return self._name

    # ── Rules of Engagement ───────────────────────────────────────────────────

    def validate_roe(self, target: str) -> bool:
        forbidden = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}
        # Block RFC-1918 private ranges
        private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                            "172.2", "172.3", "192.168.")
        if target in forbidden:
            return False
        if any(target.startswith(p) for p in private_prefixes):
            return False
        return True

    # ── Argument Validation ───────────────────────────────────────────────────

    def _validate_and_resolve_args(self, args: Optional[Dict]) -> Dict:
        """
        Validates AI-supplied args against the parameter schema.
        Returns a dict of safe, resolved values (with defaults filled in).

        Validation rules applied:
        - type coercion (integer / string)
        - min/max bounds for integers
        - allowed_values whitelist for strings
        - allowed_pattern regex for strings
        """
        resolved: Dict = {}
        ai_args = args or {}

        for param_name, schema in self.parameters.items():
            raw_value = ai_args.get(param_name, schema.get("default"))
            param_type = schema.get("type", "string")

            # ── Type Coercion ──
            if param_type == "integer":
                try:
                    value = int(raw_value)
                except (TypeError, ValueError):
                    value = int(schema.get("default", 0))

                # Bounds enforcement
                if "min" in schema and value < schema["min"]:
                    value = schema["min"]
                if "max" in schema and value > schema["max"]:
                    value = schema["max"]

            else:  # string
                value = str(raw_value) if raw_value is not None else str(schema.get("default", ""))

                # Whitelist check
                allowed: Optional[List] = schema.get("allowed_values")
                if allowed and value not in allowed:
                    # Fall back to default rather than raising — safer for AI-generated args
                    print(f"[PLUGIN:{self._name}] '{value}' not in allowed_values for '{param_name}'. Using default.")
                    value = str(schema.get("default", allowed[0]))

                # Pattern check (e.g., port ranges: digits, commas, hyphens only)
                pattern = schema.get("allowed_pattern")
                if pattern and not re.fullmatch(pattern, value):
                    print(f"[PLUGIN:{self._name}] '{value}' fails pattern '{pattern}' for '{param_name}'. Using default.")
                    value = str(schema.get("default", ""))

            resolved[param_name] = value

        return resolved

    # ── Command Construction ───────────────────────────────────────────────────

    def construct_command(self, target: str, args: Optional[Dict] = None) -> str:
        """
        Builds the final CLI command string from validated args.
        The AI provides suggestions; this method enforces the schema.
        """
        if not self.base_command:
            # Legacy fallback: simple target substitution
            return self.command_template.replace("{target}", target)

        safe_args = self._validate_and_resolve_args(args)
        safe_args["target"] = target

        try:
            command = self.base_command.format(**safe_args)
        except KeyError as e:
            raise ArgValidationError(f"Missing argument placeholder {e} in base_command for tool '{self._name}'")

        return command

    # ── Execution ──────────────────────────────────────────────────────────────

    def execute(self, target: str, args: Optional[Dict] = None) -> Any:
        """
        Builds the validated command and runs it as a subprocess.
        Uses shlex.split() for safe argument parsing (no shell=True).
        """
        # Sanitize target — strip URL schemes, trailing paths, ports
        # Tools like sublist3r, amass, etc. need bare domain/IP
        clean_target = sanitize_target(target)
        if clean_target != target:
            print(f"[PLUGIN:{self._name}] Target sanitized: '{target}' → '{clean_target}'")

        command_str = self.construct_command(clean_target, args)
        # We run the command directly inside the container (worker is already sandboxed)
        print(f"[PLUGIN:{self._name}] Executing: {command_str}")

        try:
            result = subprocess.run(
                shlex.split(command_str),
                capture_output=True,
                text=True,
                timeout=300,  # 5-minute hard timeout
            )
            return result.stdout or result.stderr
        except FileNotFoundError:
            return f"[ERROR] Binary '{self._name}' not found. Install it on your system first."
        except subprocess.TimeoutExpired:
            return f"[ERROR] Tool '{self._name}' timed out after 300 seconds."

    # ── Normalization ──────────────────────────────────────────────────────────

    def normalize(self, raw_output: str) -> Dict:
        """Wraps raw CLI output into the standard SentinelAI findings schema."""
        return {
            "raw_output": raw_output,
            "raw_tool": self._name,
            "status": "up" if raw_output and "[ERROR]" not in raw_output else "error",
        }
