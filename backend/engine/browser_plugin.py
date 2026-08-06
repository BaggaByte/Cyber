import os
import asyncio
from typing import Any, Dict, Optional
from engine.plugin_base import SecurityToolPlugin
from observability import get_logger
from evidence import upload_evidence
from playwright.async_api import async_playwright
import time

log = get_logger(__name__)

class BrowserPlugin(SecurityToolPlugin):
    """
    Phase 3: Browser Executor (Sandboxed)
    Uses Playwright to take screenshots of targets and capture DOM context.
    """
    @property
    def tool_name(self) -> str:
        return "browser"

    def validate_roe(self, target: str) -> bool:
        return True


    async def _capture_target(self, target: str):
        url = target if target.startswith("http") else f"http://{target}"
        scan_id = int(time.time())
        screenshot_path = f"/tmp/scan_{scan_id}_screenshot.png"
        dom_path = f"/tmp/scan_{scan_id}_dom.html"
        
        results = {"screenshot_url": None, "dom_url": None, "page_title": ""}

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(args=["--no-sandbox", "--disable-setuid-sandbox"])
                page = await browser.new_page()
                
                # Navigate and wait for network idle to ensure full rendering
                await page.goto(url, timeout=30000, wait_until="networkidle")
                
                results["page_title"] = await page.title()
                
                # Take screenshot
                await page.screenshot(path=screenshot_path, full_page=True)
                
                # Capture DOM
                content = await page.content()
                with open(dom_path, "w", encoding="utf-8") as f:
                    f.write(content)

                await browser.close()
                
                # Upload to MinIO Evidence Vault
                s3_key_img = f"scans/{scan_id}/screenshot_{int(time.time())}.png"
                s3_key_dom = f"scans/{scan_id}/dom_{int(time.time())}.html"
                
                upload_evidence(screenshot_path, s3_key_img, "image/png")
                upload_evidence(dom_path, s3_key_dom, "text/html")
                
                # Assuming MinIO is on port 9000
                bucket = os.environ.get("MINIO_BUCKET", "sentinel-evidence")
                results["screenshot_url"] = f"http://localhost:9000/{bucket}/{s3_key_img}"
                results["dom_url"] = f"http://localhost:9000/{bucket}/{s3_key_dom}"
                
        except Exception as e:
            log.error(f"Browser Executor failed for {url}: {e}")
            results["error"] = str(e)
        finally:
            if os.path.exists(screenshot_path):
                os.remove(screenshot_path)
            if os.path.exists(dom_path):
                os.remove(dom_path)
                
        return results

    def execute(self, target: str, args: Optional[Dict] = None) -> Any:
        """Synchronous wrapper for Celery."""
        try:
            # Playwright requires an event loop
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
        results = loop.run_until_complete(self._capture_target(target))
        
        return results

    def normalize(self, raw_results: Any) -> Dict:
        return {
            "status": "success" if not "error" in raw_results else "failed",
            "findings": [
                {
                    "type": "browser_capture",
                    "title": raw_results.get("page_title", "Unknown"),
                    "screenshot_url": raw_results.get("screenshot_url"),
                    "dom_url": raw_results.get("dom_url"),
                    "severity": "INFO",
                    "description": "Captured screenshot and DOM."
                }
            ],
            "raw_output": str(raw_results)
        }
