import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional
from engine.plugin_base import SecurityToolPlugin
from engine.generic_plugin import sanitize_target

class NmapPlugin(SecurityToolPlugin):
    
    @property
    def tool_name(self) -> str:
        return "nmap"

    def validate_roe(self, target: str) -> bool:
        """
        Rules of Engagement check. 
        Prevent scanning local/internal IPs to be safe.
        """
        forbidden_targets = ["127.0.0.1", "localhost", "0.0.0.0"]
        if target in forbidden_targets:
            return False
        return True

    def execute(self, target: str, args: Optional[Dict] = None) -> Any:
        """Runs a fast Nmap scan and returns the raw XML string."""
        target = sanitize_target(target)
        print(f"[NMAP PLUGIN] Initiating scan against {target}...")
        
        try:
            # -T4 (Aggressive), -F (Fast mode, top 100 ports), -oX - (Output XML to stdout)
            result = subprocess.run(
                ["nmap", "-T4", "-F", "-oX", "-", target],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except FileNotFoundError:
            raise Exception("Nmap binary not found. Is Nmap installed on your Windows machine and in your system PATH?")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Nmap execution failed: {e.stderr}")

    def normalize(self, raw_xml: str) -> Dict:
        """Converts Nmap's raw XML into SentinelAI's standard JSON schema."""
        findings = {"status": "down", "open_ports": [], "raw_tool": self.tool_name}
        
        if not raw_xml:
            return findings
            
        try:
            root = ET.fromstring(raw_xml)
            
            # Check if host is up
            for host in root.findall('host'):
                status = host.find('status')
                if status is not None and status.get('state') == 'up':
                    findings["status"] = "up"
                
                # Extract open ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            port_info = {
                                "port": int(port.get('portid')),
                                "protocol": port.get('protocol'),
                                "service": port.find('service').get('name') if port.find('service') is not None else "unknown"
                            }
                            findings["open_ports"].append(port_info)
                            
        except ET.ParseError:
            findings["error"] = "Failed to parse Nmap XML output"
            
        return findings