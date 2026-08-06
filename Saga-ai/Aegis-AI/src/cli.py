import os
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict
from agents.analyzer import analyze_code, verify_groq_connectivity
# 1. New Import: Bring in the HTML reporting engine
from reporter import generate_html_report

# Configuration: What to ignore and what to read
IGNORE_DIRS = {
    ".git", "node_modules", "venv", "env", "__pycache__", 
    "build", "dist", ".idea", ".vscode", "coverage"
}

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", 
    ".go", ".c", ".cpp", ".h", ".cs", ".php", ".rb"
}

def parse_directory(target_path: str) -> Dict[str, str]:
    """
    Walks the target directory, skips junk folders, and reads the content 
    of supported source code files.
    """
    base_path = Path(target_path).resolve()
    
    # Handle single file scan if target_path points to a file directly
    if base_path.exists() and base_path.is_file():
        if base_path.suffix.lower() in SUPPORTED_EXTENSIONS:
            try:
                with open(base_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if content.strip():
                        return {str(base_path.name): content}
            except Exception as e:
                print(f"[-] Could not read file {base_path.name}: {e}")
        return {}

    if not base_path.exists() or not base_path.is_dir():
        print(f"[-] Error: Directory '{target_path}' does not exist.")
        return {}

    print(f"[+] Scanning directory: {base_path}")
    file_contents = {}

    for root, dirs, files in os.walk(base_path):
        # Modify dirs in-place to prevent os.walk from traversing ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]

        for file in files:
            file_path = Path(root) / file
            
            if file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                try:
                    # Read with utf-8, ignore errors to prevent crashing on weird binary blobs
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        
                        # Only add if the file isn't empty
                        if content.strip():
                            # Store relative path for cleaner reporting
                            rel_path = str(file_path.relative_to(base_path))
                            file_contents[rel_path] = content
                            
                except Exception as e:
                    print(f"[-] Could not read {file_path.name}: {e}")

    print(f"[+] Successfully parsed {len(file_contents)} files.")
    return file_contents

def main():
    parser = argparse.ArgumentParser(
        description="Saga-ai: A Python CLI security scanner using Groq API."
    )
    parser.add_argument(
        "path",
        help="Path to the repository/directory or single file to scan"
    )
    parser.add_argument(
        "--model",
        default="GPT-OSS 120B",
        help="Groq model to use for scanning (default: GPT-OSS 120B)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Timeout in seconds for each API call (default: 600)"
    )
    # 2. Updated Arguments: Added explicit HTML reporting location
    parser.add_argument(
        "--html",
        default="report.html",
        help="Path to save the interactive HTML dashboard report (default: report.html)"
    )
    parser.add_argument(
        "--output",
        help="Optional path to write the raw backup JSON report to a file"
    )

    args = parser.parse_args()

    # Verify connection to Groq API before running the scan
    print(f"[*] Verifying Groq API connectivity...")
    if not verify_groq_connectivity():
        print("[-] Aborting scan due to connection failure with Groq API.")
        sys.exit(1)
    
    print("[+] Connection verified successfully. Proceeding to scan...")

    # Parse directory/files
    project_files = parse_directory(args.path)
    
    if not project_files:
        print("[-] No valid files found to scan.")
        sys.exit(0)

    all_findings = []
    scanned_files_count = 0

    # Iterate through the files and scan them
    for filepath, content in project_files.items():
        # Skip files that are too massive for the LLM context window
        if len(content) > 50000:
            print(f"[-] Skipping {filepath} (File too large for analysis: {len(content)} bytes)")
            continue
            
        scanned_files_count += 1
        findings = analyze_code(
            file_path=filepath,
            code_content=content,
            model=args.model,
            timeout=args.timeout
        )
        
        # Ensure findings is a list and update file path to match relative path
        if isinstance(findings, list):
            for finding in findings:
                # Fallback to filepath if model missed filling out the file field
                if not finding.get("file"):
                    finding["file"] = filepath
                all_findings.append(finding)
        else:
            print(f"[!] Warning: Model returned invalid findings format for {filepath} (expected list).")

    # Aggregate metadata structure
    report = {
        "meta": {
            "target_path": str(Path(args.path).resolve()),
            "scan_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "files_scanned": scanned_files_count,
            "findings_count": len(all_findings)
        },
        "findings": all_findings
    }

    # 3. Streamlined Output Section
    print("\n=== SCAN COMPLETE ===")
    print(f"Files Scanned: {scanned_files_count}")
    print(f"Total Vulnerabilities Found: {len(all_findings)}")
    
    # Print high-level severity metrics to terminal
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = str(f.get("severity", "LOW")).upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["LOW"] += 1
            
    print("Severity Breakdown:")
    for sev, count in severity_counts.items():
        if count > 0:
            print(f" - {sev}: {count}")

    # 4. Trigger the HTML Dashboard Generation
    print("\n[*] Compiling visual analysis report...")
    try:
        html_path = Path(args.html).resolve()
        generate_html_report(all_findings, output_filename=str(html_path))
    except Exception as e:
        print(f"[-] Failed to generate HTML dashboard: {e}")

    # 5. Keep raw JSON logging as an optional background file flag instead of flooding the terminal
    if args.output:
        try:
            output_path = Path(args.output).resolve()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"[+] Raw backup JSON saved to: {output_path}")
        except Exception as e:
            print(f"[-] Failed to write raw backup JSON to {args.output}: {e}")

if __name__ == "__main__":
    main()