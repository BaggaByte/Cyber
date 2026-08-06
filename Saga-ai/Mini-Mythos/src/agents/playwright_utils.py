'''playwright_utils.py'''
"""Utility helpers for managing a singleton Playwright Chromium browser.
Provides async functions to launch and close the browser, and to fetch page
content with proper resource cleanup.
"""
import asyncio
from typing import Tuple
from playwright.async_api import async_playwright, Browser, Page, Response

# Semaphore to limit concurrent pages (default 3)
_MAX_CONCURRENT_PAGES = 3
_page_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_PAGES)

async def get_browser() -> Tuple[Browser, asyncio.AbstractEventLoop]:
    """Launch a headless Chromium browser and return it.
    Returns a tuple of (browser, playwright_context) where the context must be
    kept alive for the lifetime of the browser and later passed to ``close_browser``.
    """
    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(headless=True)
    return browser, playwright

async def close_browser(browser: Browser, playwright) -> None:
    """Close the given browser and stop the Playwright driver."""
    await browser.close()
    await playwright.stop()

async def fetch_page(url: str, browser: Browser) -> Tuple[int, str, dict]:
    """Navigate to ``url`` using the provided ``browser`` and return status, HTML, and headers.
    The function respects a semaphore to limit the number of concurrent pages.
    ``wait_until='networkidle'`` ensures JavaScript has settled.
    """
    async with _page_semaphore:
        page: Page = await browser.new_page()
        try:
            response: Response | None = await page.goto(url, wait_until="networkidle", timeout=30000)
            status = response.status if response else 0
            headers = dict(response.headers) if response else {}
            content = await page.content()
        finally:
            await page.close()
    return status, content, headers
