import asyncio
import sys
import re
from contextvars import ContextVar
from typing import Optional

# A ContextVar that holds the asyncio.Queue for the current task/request
log_queue_var: ContextVar[Optional[asyncio.Queue]] = ContextVar("log_queue", default=None)

class ContextAwareStdout:
    """
    Custom stdout writer that intercepts sys.stdout writes.
    If the current async context has a log_queue registered, it parses
    and pushes the output as a JSON-compatible event onto that queue.
    Otherwise, it falls back to the original stdout writer.
    """
    def __init__(self, original_stdout):
        self.original_stdout = original_stdout

    def write(self, data: str):
        # Always output to real console/logs first so standard debugging is intact
        self.original_stdout.write(data)
        
        # Check if we have an active queue in the current async execution context
        queue = log_queue_var.get()
        if queue is not None and data.strip():
            # Standard print might send a line in chunks, or multiple lines.
            # We strip trailing/leading newlines and process any contentful text.
            lines = data.strip().split("\n")
            for line in lines:
                if line.strip():
                    try:
                        loop = asyncio.get_running_loop()
                        # Classify the log line to map to visual frontend styles
                        event = classify_log_line(line)
                        loop.call_soon_threadsafe(queue.put_nowait, event)
                    except RuntimeError:
                        # No running event loop (e.g. print during shutdown or non-async context)
                        pass

    def flush(self):
        self.original_stdout.flush()

    def isatty(self):
        # Delegate isatty to original stream for terminal/color compatibility checks
        return hasattr(self.original_stdout, "isatty") and self.original_stdout.isatty()

    def __getattr__(self, name):
        # Delegate any other missing attributes to the original stdout stream
        return getattr(self.original_stdout, name)

def classify_log_line(line: str) -> dict:
    """
    Analyze standard print logs from recon, hypothesis, and validation engines,
    routing them to visual levels and UI tabs.
    """
    line_clean = line.strip()
    
    # Defaults
    level = "info"
    tab = "agent"
    
    # Tab routing
    if "[HTTP]" in line_clean or "HTTP 200" in line_clean or "HTTP 302" in line_clean:
        tab = "http"
    elif "[MEMORY]" in line_clean:
        tab = "memory"
    
    # Level routing
    line_lower = line_clean.lower()
    if "[error]" in line_lower or "failed" in line_lower or "error" in line_lower or "[!]" in line_lower:
        level = "error"
    elif "warning" in line_lower or "[warn]" in line_lower or "warn:" in line_lower:
        level = "warn"
    elif "confirmed" in line_lower or "[success]" in line_lower or "success:" in line_lower or "complete" in line_lower:
        level = "success"
    elif "injecting" in line_lower or "fuzz" in line_lower or "detected" in line_lower or "evidence" in line_lower:
        level = "data"
    elif "age=" in line_lower or "cache" in line_lower or "[-] " in line_lower:
        level = "dim"

    return {
        "type": "log",
        "message": line_clean,
        "level": level,
        "tab": tab
    }

def setup_log_interceptor():
    """Hooks standard sys.stdout if not already done."""
    if not isinstance(sys.stdout, ContextAwareStdout):
        sys.stdout = ContextAwareStdout(sys.stdout)
