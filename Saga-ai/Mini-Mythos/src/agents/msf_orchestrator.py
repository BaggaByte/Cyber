from pymetasploit3.msfrpc import MsfRpcClient

# FIX: Import from the new core.logger, NOT main!
from core.logger import stream_log 

async def msf_weaponization_node(state):
    await stream_log("\n── PHASE 5 — OFFENSIVE ESCALATION ─────────────────")
    target = state.get("target", "127.0.0.1")
    findings = state.get("nuclei_findings", [])
    
    await stream_log("[MSF AGENT] Connecting to Local Metasploit RPC Server...")
    
    try:
        # Connect to the background msfrpcd server
        client = MsfRpcClient('password123', port=55553, server='127.0.0.1', ssl=True)
        await stream_log("  [+] Successfully authenticated to Metasploit API!")

        # Check if the shell was successfully caught
        sessions = client.sessions.list
        if sessions:
            await stream_log(f"  [!!!] CRITICAL: Reverse shell caught! Active sessions: {list(sessions.keys())}")
        else:
            await stream_log("  [-] Exploit completed. No reverse shell established.")

    except Exception as e:
        await stream_log(f"  [-] MSF Connection Failed: Make sure 'msfrpcd' is running in the background. Error: {str(e)}")

    return {"weaponization_complete": True}