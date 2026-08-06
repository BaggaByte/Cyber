"""
CertificatePlugin – SentinelAI dedicated TLS/SSL certificate inspector.

Uses Python's stdlib ssl + socket to extract structured certificate metadata:
  - Subject / Issuer DN
  - Subject Alternative Names (SANs) – reveals hidden related domains
  - Validity window (not_before / not_after / days_remaining / is_expired)
  - Serial number, signature algorithm, public key info
  - Full PEM chain (via openssl s_client subprocess as enrichment)

The Certificate Agent (agents.py) is the designated verifier for these findings.
"""
import socket
import ssl
import json
import datetime
import subprocess
from typing import Any, Dict, Optional
from engine.plugin_base import SecurityToolPlugin
from engine.generic_plugin import sanitize_target


class CertificatePlugin(SecurityToolPlugin):

    @property
    def tool_name(self) -> str:
        return "certcheck"

    def validate_roe(self, target: str) -> bool:
        forbidden = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}
        return target not in forbidden

    # ── Core Execution ────────────────────────────────────────────────────────

    def execute(self, target: str, args: Optional[Dict] = None) -> Any:
        """
        Connects to target:port over TLS and extracts full certificate metadata.
        Also runs openssl s_client to capture the raw chain for the evidence vault.
        """
        target = sanitize_target(target)
        port = int((args or {}).get("port", 443))
        print(f"[CERT PLUGIN] Inspecting TLS certificate for {target}:{port}...")

        result: Dict[str, Any] = {
            "target": target,
            "port": port,
            "tls_error": None,
            "certificate": {},
            "chain_pem": "",
            "openssl_output": "",
        }

        # ── 1. Python ssl – structured extraction ─────────────────────────────
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # Grab even expired/self-signed certs

            with socket.create_connection((target, port), timeout=15) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=target) as tls_sock:
                    cert_der = tls_sock.getpeercert(binary_form=True)
                    cert_dict = tls_sock.getpeercert()   # human-readable dict
                    cipher = tls_sock.cipher()
                    tls_version = tls_sock.version()

            # Parse validity dates
            fmt = "%b %d %H:%M:%S %Y %Z"
            not_before_str = cert_dict.get("notBefore", "")
            not_after_str  = cert_dict.get("notAfter", "")

            try:
                not_after_dt = datetime.datetime.strptime(not_after_str, fmt)
                not_before_dt = datetime.datetime.strptime(not_before_str, fmt)
                now = datetime.datetime.utcnow()
                days_remaining = (not_after_dt - now).days
                is_expired = days_remaining < 0
                is_expiring_soon = 0 <= days_remaining <= 30
            except Exception:
                days_remaining = None
                is_expired = None
                is_expiring_soon = None
                not_before_dt = None
                not_after_dt = None

            # Extract SANs
            san_list = []
            for san_type, san_value in cert_dict.get("subjectAltName", []):
                san_list.append({"type": san_type, "value": san_value})

            # Flatten subject/issuer tuples
            def flatten_dn(dn_tuples):
                return {k: v for tup in dn_tuples for k, v in tup}

            subject = flatten_dn(cert_dict.get("subject", []))
            issuer  = flatten_dn(cert_dict.get("issuer", []))

            result["certificate"] = {
                "subject":          subject,
                "issuer":           issuer,
                "common_name":      subject.get("commonName", ""),
                "organization":     subject.get("organizationName", ""),
                "issuer_cn":        issuer.get("commonName", ""),
                "subject_alt_names": san_list,
                "san_domains":      [s["value"] for s in san_list if s["type"] == "DNS"],
                "not_before":       str(not_before_dt),
                "not_after":        str(not_after_dt),
                "days_remaining":   days_remaining,
                "is_expired":       is_expired,
                "is_expiring_soon": is_expiring_soon,
                "serial_number":    str(cert_dict.get("serialNumber", "")),
                "ocsp":             cert_dict.get("OCSP", []),
                "ca_issuers":       cert_dict.get("caIssuers", []),
                "tls_version":      tls_version,
                "cipher_suite":     cipher[0] if cipher else None,
                "cipher_bits":      cipher[2] if cipher else None,
            }

        except ssl.SSLError as e:
            result["tls_error"] = f"SSL handshake failed: {e}"
            print(f"[CERT PLUGIN] SSL error for {target}:{port} — {e}")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result["tls_error"] = f"Connection failed: {e}"
            print(f"[CERT PLUGIN] Connection error for {target}:{port} — {e}")

        # ── 2. openssl s_client – raw chain for evidence vault ────────────────
        try:
            proc = subprocess.run(
                ["openssl", "s_client", "-connect", f"{target}:{port}",
                 "-servername", target, "-showcerts"],
                input="Q\n",
                capture_output=True, text=True, timeout=20
            )
            result["openssl_output"] = (proc.stdout or "") + (proc.stderr or "")
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            result["openssl_output"] = f"[openssl not available or timed out: {e}]"

        return result

    # ── Normalization ─────────────────────────────────────────────────────────

    def normalize(self, raw_data: Any) -> Dict:
        """
        Converts raw cert inspection dict into the SentinelAI findings schema.
        Builds a vulnerability list for near-expiry / expired / weak cipher findings.
        """
        if not isinstance(raw_data, dict):
            return {"raw_output": str(raw_data), "status": "error", "raw_tool": self.tool_name}

        cert = raw_data.get("certificate", {})
        vulns = []

        # Flag expiry issues
        is_expired = cert.get("is_expired")
        days = cert.get("days_remaining")
        if is_expired:
            vulns.append({
                "severity": "CRITICAL",
                "title": "TLS Certificate is EXPIRED",
                "detail": f"Certificate expired {abs(days)} days ago."
            })
        elif cert.get("is_expiring_soon"):
            vulns.append({
                "severity": "HIGH",
                "title": f"TLS Certificate expiring in {days} days",
                "detail": f"Expires on {cert.get('not_after')}."
            })

        # Flag weak ciphers
        bits = cert.get("cipher_bits")
        if bits and int(bits) < 128:
            vulns.append({
                "severity": "HIGH",
                "title": f"Weak cipher strength: {bits} bits",
                "detail": f"Cipher suite: {cert.get('cipher_suite')}"
            })

        # Flag self-signed (issuer == subject)
        if cert.get("issuer_cn") and cert.get("common_name"):
            if cert["issuer_cn"] == cert["common_name"]:
                vulns.append({
                    "severity": "MEDIUM",
                    "title": "Self-signed certificate detected",
                    "detail": "Certificate is not issued by a trusted CA."
                })

        # Check for TLS version
        tls_ver = cert.get("tls_version", "")
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            vulns.append({
                "severity": "HIGH",
                "title": f"Outdated TLS version: {tls_ver}",
                "detail": "TLS 1.0 and 1.1 are deprecated. Upgrade to TLS 1.2 or 1.3."
            })

        if raw_data.get("tls_error"):
            vulns.append({
                "severity": "HIGH",
                "title": "TLS connection error",
                "detail": raw_data["tls_error"]
            })

        return {
            "status": "error" if raw_data.get("tls_error") and not cert else "up",
            "raw_tool": self.tool_name,
            "target": raw_data.get("target"),
            "port": raw_data.get("port"),
            "certificate": cert,
            "san_domains": cert.get("san_domains", []),
            "vulnerabilities": vulns,
            "openssl_raw": raw_data.get("openssl_output", ""),
            "tls_error": raw_data.get("tls_error"),
        }
