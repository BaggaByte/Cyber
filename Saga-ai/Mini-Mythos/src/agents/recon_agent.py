"""
Advanced Active Recon Engine — v3.0
=====================================
Authorized use only — run only against systems you own or have
explicit written permission to test.

Upgrades over v1:
 - Multi-depth BFS crawler (configurable depth + page limit)
 - JavaScript endpoint extraction (inline scripts + .js files)
 - robots.txt + sitemap.xml parsing
 - API endpoint discovery (common path wordlist + REST pattern detection)
 - HTTP header fingerprinting (WAF, server, framework, CSP, CORS misconfig)
 - Form analysis: hidden fields, CSRF tokens, file uploads, multipart
 - URL parameter extraction from anchor hrefs
 - Technology stack detection (cookies, headers, HTML meta, JS globals)
 - Rate limiter (async token bucket)
 - Structured AppModel dataclass with JSON export
 - Async-safe, fully typed
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import httpx
from bs4 import BeautifulSoup

# Playwright utilities for dynamic rendering
from .playwright_utils import fetch_page, get_browser, close_browser

# ──────────────────────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────────────────────

@dataclass
class ReconConfig:
    max_depth:       int   = 3          # BFS crawl depth
    max_pages:       int   = 100        # hard cap on pages crawled
    timeout:         float = 15.0
    rate_limit_rps:  float = 5.0        # requests per second
    follow_redirects:bool  = True
    verify_ssl:      bool  = False
    crawl_js_files:  bool  = True       # fetch + parse linked .js files
    check_robots:    bool  = True       # parse robots.txt
    check_sitemap:   bool  = True       # parse sitemap.xml
    api_wordlist:    bool  = True       # probe common API paths
    max_js_files:    int   = 10         # cap .js files fetched
    export_json:     bool  = True
    output_file:     str   = "recon_output.json"


DEFAULT_CONFIG = ReconConfig()

_CRAWL_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "close",
}


# ──────────────────────────────────────────────────────────────
# DATA MODELS
# ──────────────────────────────────────────────────────────────

@dataclass
class FormInfo:
    action:        str
    method:        str                         # GET / POST
    params:        list[str]
    hidden_params: list[str]                   # hidden inputs
    has_csrf:      bool                        # csrf token detected?
    has_file_upload: bool                      # file input present?
    enctype:       str                         # application/x-www-form-urlencoded | multipart/form-data


@dataclass
class EndpointInfo:
    url:         str
    method:      str   = "GET"
    source:      str   = "crawl"               # crawl | form | js | robots | sitemap | wordlist | href_param
    params:      list[str] = field(default_factory=list)
    status_code: int   = 0
    depth:       int   = 0


@dataclass
class TechStack:
    server:         str        = "unknown"
    language:       str        = "unknown"
    framework:      str        = "unknown"
    db_hint:        str        = "unknown"
    waf:            str        = "none"
    cdn:            str        = "none"
    cms:            str        = "unknown"
    js_libs:        list[str]  = field(default_factory=list)
    cookies:        list[str]  = field(default_factory=list)
    security_headers_missing: list[str] = field(default_factory=list)
    cors_misconfig: bool       = False


@dataclass
class AppModel:
    base_url:         str
    scan_time:        str              = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    endpoints:        list[EndpointInfo] = field(default_factory=list)
    forms:            list[FormInfo]     = field(default_factory=list)
    inputs:           dict               = field(default_factory=dict)   # legacy compat
    trust_boundaries: list[str]          = field(default_factory=lambda: ["unauthenticated"])
    tech_stack:       TechStack          = field(default_factory=TechStack)
    robots_entries:   list[str]          = field(default_factory=list)
    sitemap_urls:     list[str]          = field(default_factory=list)
    js_endpoints:     list[str]          = field(default_factory=list)
    api_endpoints:    list[str]          = field(default_factory=list)
    url_params:       dict               = field(default_factory=dict)   # url → [params]
    crawl_errors:     list[str]          = field(default_factory=list)
    pages_crawled:    int                = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        # Convert EndpointInfo list to plain dicts
        d["endpoints"] = [asdict(e) for e in self.endpoints]
        d["forms"]     = [asdict(f) for f in self.forms]
        d["tech_stack"] = asdict(self.tech_stack)
        return d

    def summary(self) -> str:
        return (
            f"Pages crawled    : {self.pages_crawled}\n"
            f"Endpoints found  : {len(self.endpoints)}\n"
            f"Forms found      : {len(self.forms)}\n"
            f"JS endpoints     : {len(self.js_endpoints)}\n"
            f"API endpoints    : {len(self.api_endpoints)}\n"
            f"robots.txt paths : {len(self.robots_entries)}\n"
            f"URL params found : {sum(len(v) for v in self.url_params.values())}\n"
            f"Tech stack       : {self.tech_stack.language} / "
            f"{self.tech_stack.framework} / {self.tech_stack.server}\n"
            f"WAF              : {self.tech_stack.waf}\n"
            f"CORS misconfig   : {self.tech_stack.cors_misconfig}\n"
            f"Errors           : {len(self.crawl_errors)}"
        )


# ──────────────────────────────────────────────────────────────
# RATE LIMITER
# ──────────────────────────────────────────────────────────────

class AsyncRateLimiter:
    def __init__(self, rps: float):
        self._interval = 1.0 / rps
        self._last: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            wait = self._interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


# ──────────────────────────────────────────────────────────────
# FINGERPRINTING
# ──────────────────────────────────────────────────────────────

_WAF_SIGS = {
    "Cloudflare":   ["cf-ray", "__cfduid", "cloudflare"],
    "AWS WAF":      ["x-amzn-requestid", "x-amz-cf-id"],
    "Akamai":       ["akamai-origin-hop", "x-akamai"],
    "Sucuri":       ["x-sucuri-id"],
    "ModSecurity":  ["mod_security", "modsecurity"],
    "Imperva":      ["x-iinfo", "incap_ses"],
    "F5 BIG-IP":    ["bigipserver", "x-wa-info"],
}

_FRAMEWORK_SIGS = {
    "Laravel":    ["laravel_session", "x-powered-by: php"],
    "Django":     ["csrfmiddlewaretoken", "django"],
    "WordPress":  ["wp-content", "wp-login", "wp-json"],
    "Express.js": ["x-powered-by: express"],
    "Spring":     ["x-application-context", "jsessionid"],
    "ASP.NET":    ["x-aspnet-version", "__viewstate", "aspxauth"],
    "Rails":      ["x-request-id", "_rails_session", "x-runtime"],
    "Flask":      ["werkzeug", "x-powered-by: flask"],
    "Next.js":    ["x-nextjs", "__next"],
    "Nuxt":       ["x-nuxt", "__nuxt"],
}

_JS_LIB_SIGS = {
    "jQuery":      r"jquery[.-](\d+\.\d+)",
    "React":       r"react[.-](\d+\.\d+)",
    "Vue.js":      r"vue[.-](\d+\.\d+)",
    "Angular":     r"angular[.-](\d+\.\d+)",
    "Bootstrap":   r"bootstrap[.-](\d+\.\d+)",
    "Lodash":      r"lodash[.-](\d+\.\d+)",
    "Axios":       r"axios[.-](\d+\.\d+)",
}

_SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

_CSRF_PATTERNS = re.compile(
    r"csrf|_token|xsrf|authenticity_token", re.IGNORECASE
)


def fingerprint(resp: httpx.Response, soup: Optional[BeautifulSoup] = None) -> TechStack:
    ts = TechStack()
    hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}
    body_lower = resp.text[:8000].lower()

    # Server
    ts.server = hdrs.get("server", "unknown")

    # Language / runtime
    powered = hdrs.get("x-powered-by", "")
    if powered:
        ts.language = powered
    elif "php" in body_lower or ".php" in resp.url.path:
        ts.language = "PHP"
    elif "asp.net" in str(hdrs):
        ts.language = "ASP.NET"
    elif "rack" in hdrs.get("server", ""):
        ts.language = "Ruby"

    # Framework
    for fw, sigs in _FRAMEWORK_SIGS.items():
        if any(s.lower() in str(hdrs) or s.lower() in body_lower for s in sigs):
            ts.framework = fw
            break

    # WAF
    for waf, sigs in _WAF_SIGS.items():
        if any(s in str(hdrs) or s in body_lower for s in sigs):
            ts.waf = waf
            break

    # CDN
    if "cloudflare" in str(hdrs):
        ts.cdn = "Cloudflare"
    elif "x-cache" in hdrs and "cloudfront" in hdrs.get("x-cache", ""):
        ts.cdn = "AWS CloudFront"
    elif "x-fastly" in hdrs:
        ts.cdn = "Fastly"

    # CMS
    if "wp-content" in body_lower or "wp-json" in body_lower:
        ts.cms = "WordPress"
    elif "joomla" in body_lower:
        ts.cms = "Joomla"
    elif "drupal" in body_lower:
        ts.cms = "Drupal"

    # Cookies
    for h, v in resp.headers.multi_items():
        if h.lower() == "set-cookie":
            ts.cookies.append(v.split(";")[0].split("=")[0])

    # DB hints from error messages or stack traces
    for db in ["mysql", "postgresql", "sqlite", "oracle", "mssql", "mongodb"]:
        if db in body_lower:
            ts.db_hint = db.upper()
            break

    # JS libraries from HTML
    if soup:
        for script in soup.find_all("script", src=True):
            src = script["src"].lower()
            for lib, pattern in _JS_LIB_SIGS.items():
                if re.search(pattern, src):
                    if lib not in ts.js_libs:
                        ts.js_libs.append(lib)

    # Missing security headers
    ts.security_headers_missing = [
        h for h in _SECURITY_HEADERS if h not in hdrs
    ]

    # CORS misconfiguration
    origin = hdrs.get("access-control-allow-origin", "")
    if origin in ("*", "null") or "credentials" in hdrs.get("access-control-allow-credentials", ""):
        ts.cors_misconfig = True

    return ts


# ──────────────────────────────────────────────────────────────
# JS ENDPOINT EXTRACTION
# ──────────────────────────────────────────────────────────────

# Patterns: REST paths, API routes, fetch/XHR calls
_JS_ENDPOINT_PATTERNS = [
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete)|http\.(?:get|post))\s*\(\s*['"`]([^'"`]+)['"`]"""),
    re.compile(r"""(?:url|endpoint|api_url|apiUrl|baseUrl|path)\s*[:=]\s*['"`]([/][^'"`\s]{2,})['"`]"""),
    re.compile(r"""['"`](/(?:api|v\d|rest|graphql|admin|user|auth)[^'"`\s]{0,80})['"`]"""),
    re.compile(r"""router\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]"""),
]


def extract_js_endpoints(js_content: str, base_url: str) -> list[str]:
    found: list[str] = []
    for pattern in _JS_ENDPOINT_PATTERNS:
        for match in pattern.finditer(js_content):
            path = match.group(1).strip()
            if path and not path.startswith(("http://example", "//", "data:")):
                full = urljoin(base_url, path) if path.startswith("/") else path
                if full not in found:
                    found.append(full)
    return found


# ──────────────────────────────────────────────────────────────
# URL PARAMETER EXTRACTION
# ──────────────────────────────────────────────────────────────

def extract_url_params(url: str) -> list[str]:
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    return params


def clean_url(url: str) -> str:
    """Return URL with query string stripped — for endpoint deduplication."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


# ──────────────────────────────────────────────────────────────
# COMMON API WORDLIST
# ──────────────────────────────────────────────────────────────

_API_WORDLIST = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/user", "/api/me", "/api/profile",
    "/api/login", "/api/auth", "/api/token", "/api/refresh",
    "/api/admin", "/api/config", "/api/settings",
    "/api/orders", "/api/products", "/api/items",
    "/graphql", "/graphiql", "/playground",
    "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json",
    "/.well-known/openid-configuration",
    "/actuator", "/actuator/health", "/actuator/env",   # Spring Boot
    "/metrics", "/health", "/status", "/ping",
    "/admin", "/admin/login", "/admin/panel",
    "/wp-json/wp/v2/users",                              # WordPress REST
    "/xmlrpc.php",
    "/.env", "/config.json", "/config.php",
    "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info",                   # Apache status
    "/__debug__/", "/debug/",                            # Django debug
]


async def probe_api_paths(
    base_url: str,
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
) -> list[str]:
    """Probe common API + admin paths. Only returns paths that respond 2xx/3xx."""
    found: list[str] = []
    base = base_url.rstrip("/")

    tasks = []
    for path in _API_WORDLIST:
        url = base + path
        tasks.append(_probe_one(url, client, rl))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for url, result in zip(
        [base + p for p in _API_WORDLIST], results
    ):
        if isinstance(result, int) and result < 400:
            found.append(url)

    return found


async def _probe_one(
    url: str, client: httpx.AsyncClient, rl: AsyncRateLimiter
) -> int:
    await rl.acquire()
    try:
        resp = await client.head(url)
        return resp.status_code
    except Exception:
        return 0


# ──────────────────────────────────────────────────────────────
# ROBOTS.TXT PARSER
# ──────────────────────────────────────────────────────────────

async def parse_robots(
    base_url: str, client: httpx.AsyncClient, rl: AsyncRateLimiter
) -> list[str]:
    paths: list[str] = []
    await rl.acquire()
    try:
        resp = await client.get(base_url.rstrip("/") + "/robots.txt")
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("allow:", "disallow:")):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        path = parts[1].strip()
                        if path and path != "/":
                            full = urljoin(base_url, path)
                            if full not in paths:
                                paths.append(full)
    except Exception:
        pass
    return paths


# ──────────────────────────────────────────────────────────────
# SITEMAP.XML PARSER
# ──────────────────────────────────────────────────────────────

async def parse_sitemap(
    base_url: str, client: httpx.AsyncClient, rl: AsyncRateLimiter
) -> list[str]:
    urls: list[str] = []
    await rl.acquire()
    try:
        resp = await client.get(base_url.rstrip("/") + "/sitemap.xml")
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "xml")
            for loc in soup.find_all("loc"):
                u = loc.get_text(strip=True)
                if u and u not in urls:
                    urls.append(u)
    except Exception:
        pass
    return urls


# ──────────────────────────────────────────────────────────────
# FORM ANALYZER
# ──────────────────────────────────────────────────────────────

def analyze_form(form_tag, base_url: str) -> FormInfo:
    action = urljoin(base_url, form_tag.get("action", "") or base_url)
    method = form_tag.get("method", "GET").upper()
    enctype = form_tag.get("enctype", "application/x-www-form-urlencoded").lower()

    all_inputs  = form_tag.find_all(["input", "select", "textarea", "button"])
    params: list[str]         = []
    hidden_params: list[str]  = []
    has_csrf                  = False
    has_file_upload           = False

    for inp in all_inputs:
        name  = inp.get("name", "")
        itype = inp.get("type", "text").lower()
        if not name:
            continue

        if itype == "hidden":
            hidden_params.append(name)
            if _CSRF_PATTERNS.search(name):
                has_csrf = True
        elif itype == "file":
            has_file_upload = True
            params.append(name)
        elif itype not in ("submit", "button", "image", "reset"):
            params.append(name)

    return FormInfo(
        action         = action,
        method         = method,
        params         = list(set(params)),
        hidden_params  = list(set(hidden_params)),
        has_csrf       = has_csrf,
        has_file_upload= has_file_upload,
        enctype        = enctype,
    )


# ──────────────────────────────────────────────────────────────
# BFS CRAWLER
# ──────────────────────────────────────────────────────────────

async def _crawl_page(
    url: str,
    depth: int,
    base_host: str,
    browser,  # Playwright Browser instance
    rl: AsyncRateLimiter,
    model: AppModel,
    visited: set[str],
    queue: deque,
    js_queue: set[str],
    cfg: ReconConfig,
    fingerprinted: list[bool],
):
    clean = clean_url(url)
    if clean in visited:
        return
    visited.add(clean)
    model.pages_crawled += 1

    await rl.acquire()
    try:
        status, content, headers = await fetch_page(url, browser)
        # Simulate httpx.Response like object for downstream code
        class SimpleResponse:
            def __init__(self, status, text, headers, url):
                self.status_code = status
                self.text = text
                self.headers = headers
                self.url = httpx.URL(url)
                # Store raw bytes for compatibility with original code
                self.content = text.encode() if isinstance(text, str) else text
        resp = SimpleResponse(status, content, headers, url)
    except Exception as e:
        print(f"\n[CRITICAL RECON ERROR] The crawler crashed because: {e}\n")
        model.crawl_errors.append(f"{type(e).__name__}: {url} — {e}")
        return

    print(
        f"  [CRAWL d={depth}] HTTP {resp.status_code} "
        f"{len(resp.content):>7} bytes  {url}"
    )

    if resp.status_code >= 400:
        return

    # Playwright returns headers as dict; ensure case-insensitivity similar to httpx
    content_type = resp.headers.get("content-type", "")
    if "html" not in content_type:
        return

    soup = BeautifulSoup(resp.text, "html.parser")

    # Fingerprint only on root / first page
    if not fingerprinted[0]:
        model.tech_stack = fingerprint(resp, soup)
        fingerprinted[0] = True

    # URL params from this page's URL
    url_params = extract_url_params(url)
    if url_params:
        ep_clean = clean_url(url)
        existing = model.url_params.get(ep_clean, [])
        model.url_params[ep_clean] = list(set(existing + url_params))

    # Register endpoint
    ep_info = EndpointInfo(
        url         = clean_url(url),
        method      = "GET",
        source      = "crawl",
        params      = url_params,
        status_code = resp.status_code,
        depth       = depth,
    )
    if not any(e.url == ep_info.url for e in model.endpoints):
        model.endpoints.append(ep_info)

    # Forms
    for form_tag in soup.find_all("form"):
        fi = analyze_form(form_tag, url)
        if not any(f.action == fi.action for f in model.forms):
            model.forms.append(fi)
            # Legacy inputs dict
            model.inputs[fi.action] = {
                "params": fi.params + fi.hidden_params,
                "method": fi.method,
                "has_csrf": fi.has_csrf,
                "has_file_upload": fi.has_file_upload,
            }
            ep = EndpointInfo(
                url    = clean_url(fi.action),
                method = fi.method,
                source = "form",
                params = fi.params,
                depth  = depth,
            )
            if not any(e.url == ep.url for e in model.endpoints):
                model.endpoints.append(ep)

    # Anchor links
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        full = urljoin(url, href)
        parsed = urlparse(full)
        if parsed.netloc != base_host:
            continue
        # Extract URL params even if we won't crawl deeper
        params = extract_url_params(full)
        if params:
            c = clean_url(full)
            model.url_params[c] = list(set(model.url_params.get(c, []) + params))

        c = clean_url(full)
        if c not in visited and depth < cfg.max_depth and model.pages_crawled < cfg.max_pages:
            queue.append((full, depth + 1))

    # Collect .js files for later processing
    if cfg.crawl_js_files:
        for script in soup.find_all("script", src=True):
            src = urljoin(url, script["src"])
            if urlparse(src).netloc == base_host:
                js_queue.add(src)

    # Inline script endpoint extraction
    for script in soup.find_all("script", src=False):
        js_text = script.get_text()
        if js_text:
            for ep_str in extract_js_endpoints(js_text, model.base_url):
                if ep_str not in model.js_endpoints:
                    model.js_endpoints.append(ep_str)


# ──────────────────────────────────────────────────────────────
# JS FILE PROCESSOR
# ──────────────────────────────────────────────────────────────

async def _process_js_files(
    js_queue: set[str],
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
    model: AppModel,
    cfg: ReconConfig,
):
    processed = 0
    for js_url in js_queue:
        if processed >= cfg.max_js_files:
            break
        await rl.acquire()
        try:
            resp = await client.get(js_url)
            if resp.status_code == 200:
                endpoints = extract_js_endpoints(resp.text, model.base_url)
                new = [e for e in endpoints if e not in model.js_endpoints]
                model.js_endpoints.extend(new)
                if new:
                    print(f"  [JS] {js_url} → {len(new)} new endpoints")
        except Exception as e:
            model.crawl_errors.append(f"JS fetch failed: {js_url} — {e}")
        processed += 1


# ──────────────────────────────────────────────────────────────
# MAIN ENGINE
# ──────────────────────────────────────────────────────────────

async def active_recon_engine(
    target_url: str,
    cfg: ReconConfig = DEFAULT_CONFIG,
) -> AppModel:
    """
    Full multi-phase recon pipeline:
      Phase 1 — BFS crawl (multi-depth) using Playwright for rendering
      Phase 2 — JS file endpoint extraction
      Phase 3 — robots.txt + sitemap.xml
      Phase 4 — API wordlist probing
      Phase 5 — Tech fingerprinting (already done inline in phase 1)
    """
    base = target_url.rstrip("/")
    base_host = urlparse(base).netloc

    print(f"\n{'='*60}")
    print(f"  RECON ENGINE v3.0 — Target: {base}")
    print(f"  depth={cfg.max_depth} | pages={cfg.max_pages} | rps={cfg.rate_limit_rps}")
    print(f"{'='*60}\n")

    model = AppModel(base_url=base)
    rl = AsyncRateLimiter(cfg.rate_limit_rps)
    visited: set[str] = set()
    queue: deque = deque([(base, 0)])
    js_queue: set[str] = set()
    fingerprinted = [False]

    # Launch Playwright browser (singleton) and httpx client
    browser, playwright = await get_browser()
    async with httpx.AsyncClient(
        headers=_CRAWL_HEADERS,
        verify=cfg.verify_ssl,
        timeout=cfg.timeout,
        follow_redirects=True,
    ) as client:

        # ── Phase 1: BFS Crawl ────────────────────────────────
        print("[PHASE 1] BFS Crawl")
        while queue and model.pages_crawled < cfg.max_pages:
            url, depth = queue.popleft()
            await _crawl_page(
                url, depth, base_host, browser, rl,
                model, visited, queue, js_queue, cfg, fingerprinted
            )

        # ── Phase 2: JS File Analysis ─────────────────────────
        if cfg.crawl_js_files and js_queue:
            print(f"\n[PHASE 2] JS File Analysis ({len(js_queue)} files found)")
            await _process_js_files(js_queue, client, rl, model, cfg)

        # ── Phase 3: robots.txt + sitemap.xml ─────────────────
        print("\n[PHASE 3] robots.txt + sitemap.xml")
        if cfg.check_robots:
            model.robots_entries = await parse_robots(base, client, rl)
            print(f"  robots.txt: {len(model.robots_entries)} entries")

        if cfg.check_sitemap:
            model.sitemap_urls = await parse_sitemap(base, client, rl)
            print(f"  sitemap.xml: {len(model.sitemap_urls)} URLs")

        # ── Phase 4: API Wordlist Probing ─────────────────────
        if cfg.api_wordlist:
            print(f"\n[PHASE 4] API Wordlist ({len(_API_WORDLIST)} paths)")
            model.api_endpoints = await probe_api_paths(base, client, rl)
            print(f"  Live API paths: {len(model.api_endpoints)}")

    # Close Playwright browser
    await close_browser(browser, playwright)



    # ── Post-processing ───────────────────────────────────────
    # Add robots + sitemap URLs as endpoints if same host
    for url in model.robots_entries + model.sitemap_urls:
        if urlparse(url).netloc == base_host:
            c = clean_url(url)
            if not any(e.url == c for e in model.endpoints):
                model.endpoints.append(EndpointInfo(
                    url=c, source="robots/sitemap", depth=0
                ))

    # Add JS-discovered endpoints
    for ep in model.js_endpoints:
        if urlparse(ep).netloc in ("", base_host):
            c = clean_url(ep)
            if not any(e.url == c for e in model.endpoints):
                model.endpoints.append(EndpointInfo(
                    url=c, source="js", depth=0
                ))

    # Deduplicate full endpoint list
    seen_urls: set[str] = set()
    deduped: list[EndpointInfo] = []
    for ep in model.endpoints:
        if ep.url not in seen_urls:
            seen_urls.add(ep.url)
            deduped.append(ep)
    model.endpoints = deduped

    # Summary
    separator = "-" * 60
    print(f"\n{separator}")
    print("  RECON SUMMARY")
    print(separator)
    print(model.summary())

    # Export
    if cfg.export_json:
        with open(cfg.output_file, "w", encoding="utf-8") as f:
            json.dump(model.to_dict(), f, indent=2, default=str)
        print(f"\n  [REPORT] Saved -> {cfg.output_file}")

    return model


# ──────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    TARGET = "http://testphp.vulnweb.com"    # CHANGE TO YOUR AUTHORIZED TARGET

    cfg = ReconConfig(
        max_depth      = 3,
        max_pages      = 80,
        rate_limit_rps = 4.0,
        crawl_js_files = True,
        check_robots   = True,
        check_sitemap  = True,
        api_wordlist   = True,
        export_json    = True,
        output_file    = "recon_output.json",
    )

    import asyncio
    asyncio.run(active_recon_engine(TARGET, cfg))