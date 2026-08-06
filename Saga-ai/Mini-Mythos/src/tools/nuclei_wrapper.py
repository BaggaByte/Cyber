import asyncio
import json
import shutil

async def run_nuclei_scan(target_url: str, template_tags: str = "cves,vuln,sqli,xss,misconfiguration,exposures") -> list:
    """
    Executes the ProjectDiscovery Nuclei binary via subprocess.
    Captures the stdout, parses the JSON lines, and returns the findings.
    """
    print(f"\n[NUCLEI ENGINE] Arming ProjectDiscovery Nuclei for target: {target_url}")
    print(f"  [+] Active Template Tags: {template_tags}")
    
    # Check if nuclei is installed on the system path
    if not shutil.which("nuclei"):
        print("  [!] WARNING: 'nuclei' binary not found in system PATH.")
        print("  [!] Falling back to Simulated Nuclei Execution for Demo Mode...")
        await asyncio.sleep(2)
        # Mock Nuclei JSON Output for portfolio demos
        return [{
            "info": {
                "name": "Exposed Git Repository",
                "severity": "high",
                "tags": ["exposure", "git"]
            },
            "type": "http",
            "host": target_url,
            "matched-at": f"{target_url}/.git/config"
        }]

    # Real Execution Logic
    cmd = [
        "nuclei",
        "-u", target_url,
        "-tags", template_tags,
        "-jsonl",                 # CORRECTED: Output JSON lines directly to stdout
        "-silent"                 # Suppress banner and standard logs
    ]

    print(f"  [*] Executing: {' '.join(cmd)}")
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            # Hard 60-second deadline: if Nuclei hangs waiting on a slow/unreachable
            # host, kill it and return gracefully instead of blocking the agent forever.
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60.0)
        except asyncio.TimeoutError:
            print("  [!] Nuclei timed out after 60 s! Killing process and returning empty results.")
            process.kill()
            return []

        findings = []
        
        if stdout:
            # CORRECTED: Added explicit utf-8 decoding with 'replace' to prevent crashes on weird bytes
            lines = stdout.decode('utf-8', errors='replace').strip().split('\n')
            for line in lines:
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                        
        print(f"  [+] Nuclei scan complete. Discovered {len(findings)} findings.")
        return findings

    except Exception as e:
        print(f"  [-] Nuclei Execution Failed: {str(e)}")
        return []