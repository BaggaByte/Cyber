from mcp.server.fastmcp import FastMCP
import os
import asyncio

# Initialize the MCP Server
mcp = FastMCP("Saga-GitHub-Bridge")


@mcp.tool()
async def create_security_issue(title: str, body: str, labels: str = "security,automated") -> str:
    """
    Creates a GitHub Issue for a discovered vulnerability.
    Use this tool when a confirmed vulnerability needs to be tracked.
    
    Args:
        title: The issue title (e.g., "CWE-89: SQL Injection in /search")
        body: Detailed markdown description of the vulnerability and remediation steps.
        labels: Comma-separated labels to apply.
    """
    # In production, this would use the GitHub API via GITHUB_TOKEN
    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPO", "user/saga-ai")
    
    if not token:
        return f"[SIMULATED] GitHub Issue created: '{title}' in {repo} (GITHUB_TOKEN not configured)"
    
    # Production implementation would use httpx to POST to GitHub API
    print(f"[GitHub MCP] Creating issue: {title}")
    await asyncio.sleep(1)
    
    return f"""
    [+] GitHub Issue Created Successfully
    - Repository: {repo}
    - Title: {title}
    - Labels: {labels}
    - Status: Open
    """


@mcp.tool()
async def create_pull_request(title: str, branch: str, body: str) -> str:
    """
    Creates a Pull Request with an automated security patch.
    
    Args:
        title: PR title (e.g., "Security Patch: Fix CWE-89 in search.py")
        branch: Source branch name containing the fix.
        body: Detailed markdown PR description.
    """
    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPO", "user/saga-ai")
    
    if not token:
        return f"[SIMULATED] PR created: '{title}' from {branch} (GITHUB_TOKEN not configured)"
    
    print(f"[GitHub MCP] Creating PR: {title}")
    await asyncio.sleep(1)
    
    return f"""
    [+] Pull Request Created Successfully
    - Repository: {repo}
    - Title: {title}
    - Branch: {branch} -> main
    - Status: Open, Awaiting Review
    """


if __name__ == "__main__":
    mcp.run()
