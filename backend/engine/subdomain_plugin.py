import socket
from typing import Any, Dict, Optional
from engine.plugin_base import SecurityToolPlugin
from engine.generic_plugin import sanitize_target

class SubdomainPlugin(SecurityToolPlugin):
    
    @property
    def tool_name(self) -> str:
        return "subdomain"

    def validate_roe(self, target: str) -> bool:
        """Rules of Engagement: Block internal/local scanning."""
        forbidden = ["127.0.0.1", "localhost", "0.0.0.0"]
        return target not in forbidden

    def execute(self, target: str, args: Optional[Dict] = None) -> Any:
        """
        Enumerates common subdomains using native DNS resolution.
        Avoids external binary dependencies for clean multi-platform execution.
        """
        target = sanitize_target(target)
        print(f"[SUBDOMAIN PLUGIN] Enumerating assets for: {target}...")
        
        # Common target subdomains for security mapping
        common_prefixes = [
            "www", "mail", "remote", "blog", "webmail", "server",
            "ns1", "ns2", "smtp", "vpn", "secure", "api", "dev",
            "staging", "admin", "portal", "cloud", "autodiscover"
        ]
        
        found_subdomains = []
        
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{target}"
            try:
                # Attempt standard system DNS lookup
                ip_address = socket.gethostbyname(subdomain)
                found_subdomains.append({
                    "subdomain": subdomain,
                    "ip": ip_address
                })
            except socket.gaierror:
                # Subdomain does not exist or did not resolve
                continue
                
        return found_subdomains

    def normalize(self, raw_data: list) -> Dict:
        """Converts raw socket lists into standardized SentinelAI JSON format."""
        return {
            "status": "up" if len(raw_data) > 0 else "unknown",
            "discovered_subdomains": raw_data,
            "raw_tool": self.tool_name
        }
