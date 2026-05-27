"""
ZombieGuard — URL / API Link Scanner Service
Feature 1: Manually provide a website URL or API base URL to scan
Uses: requests + BeautifulSoup to discover endpoints, then runs full ML pipeline
"""
import re
import time
import random
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel, HttpUrl, field_validator


# ── Pydantic request model ────────────────────────────────────────────────────
class URLScanRequest(BaseModel):
    url: str                              # website or API base URL
    scan_type: str = "auto"              # auto | swagger | api | website
    max_endpoints: int = 50             # cap for safety
    contamination: float = 0.15
    staleness_days: int = 30
    auto_disable: bool = True
    rotate_keys: bool = True
    fire_webhook: bool = True

    @field_validator("url")
    @classmethod
    def clean_url(cls, v):
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v

    @field_validator("max_endpoints")
    @classmethod
    def cap_endpoints(cls, v):
        return min(max(1, v), 100)


# ── Common API path patterns to probe ─────────────────────────────────────────
COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml", "/swagger.json",
    "/api/docs", "/docs", "/redoc",
    "/graphql", "/graphql/schema",
    "/api/health", "/health", "/status",
    "/api/users", "/api/products", "/api/orders",
    "/api/payments", "/api/accounts", "/api/auth",
    "/api/login", "/api/logout", "/api/register",
    "/api/search", "/api/upload", "/api/download",
    "/.well-known/openapi", "/.well-known/swagger",
    "/api/admin", "/api/internal", "/api/metrics",
    "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/api/v2/users", "/api/v2/products", "/api/v2/payments",
    "/rest/api", "/rest/v1", "/rest/v2",
    "/services/api", "/backend/api", "/server/api",
]

# ── Regex patterns to find API routes in HTML/JS source ───────────────────────
API_ROUTE_PATTERNS = [
    r'["\'](/api/[a-zA-Z0-9/_\-{}.]+)["\']',
    r'["\'](/v\d+/[a-zA-Z0-9/_\-{}.]+)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    r'url:\s*["\']([^"\']+)["\']',
    r'endpoint:\s*["\']([^"\']+)["\']',
    r'path:\s*["\']([/][^"\']+)["\']',
    r'"(\/[a-zA-Z0-9_\-]+\/[a-zA-Z0-9_\-\/{}]+)"',
]

HEADERS = {
    "User-Agent": "ZombieGuard-API-Scanner/1.0 (Security Research Tool)",
    "Accept": "text/html,application/json,application/yaml,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


class URLAPIScanner:
    """
    Scans a given URL to discover API endpoints using:
    1. BeautifulSoup HTML/JS parsing — finds API routes in page source
    2. Swagger/OpenAPI doc detection — parses documented endpoints
    3. Common path probing — checks well-known API paths
    4. JS source scanning — regex finds fetch/axios calls
    """

    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def _safe_get(self, url: str) -> Optional[requests.Response]:
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
            return r
        except Exception:
            return None

    def _parse_swagger(self, base_url: str) -> list[dict]:
        """Try to fetch and parse Swagger/OpenAPI JSON spec."""
        endpoints = []
        swagger_paths = [
            "/openapi.json", "/swagger.json", "/api/openapi.json",
            "/api/swagger.json", "/v1/openapi.json", "/v2/openapi.json",
            "/api/v1/openapi.json", "/api/v2/openapi.json",
        ]
        for path in swagger_paths:
            url = base_url.rstrip("/") + path
            r = self._safe_get(url)
            if not r or r.status_code != 200:
                continue
            try:
                spec = r.json()
                paths = spec.get("paths", {})
                base_path = spec.get("basePath", "")
                for route, methods in paths.items():
                    for method, info in methods.items():
                        if method.upper() not in ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"]:
                            continue
                        ep_path = base_path + route
                        security = info.get("security", spec.get("security", None))
                        has_auth = security is not None and len(security) > 0
                        endpoints.append({
                            "endpoint": ep_path,
                            "method": method.upper(),
                            "has_auth": has_auth,
                            "is_documented": True,
                            "is_registered": True,
                            "source": f"swagger:{path}",
                            "description": info.get("summary", ""),
                        })
                if endpoints:
                    break
            except Exception:
                continue
        return endpoints

    def _extract_from_html(self, html: str, base_url: str) -> list[str]:
        """Use BeautifulSoup + regex to extract API paths from HTML source."""
        found = set()
        soup = BeautifulSoup(html, "html.parser")

        # Scan all text content + script tags
        full_text = html
        for pattern in API_ROUTE_PATTERNS:
            matches = re.findall(pattern, full_text)
            for m in matches:
                if len(m) > 3 and m.startswith("/") and not m.startswith("//"):
                    # Filter out static assets
                    if not any(m.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".ico", ".svg", ".woff"]):
                        found.add(m.split("?")[0].split("#")[0])  # strip query/fragment

        # Scan <a href>, <form action>, data-* attributes
        for tag in soup.find_all(["a", "form", "button"]):
            href = tag.get("href") or tag.get("action") or tag.get("data-url") or ""
            if href and href.startswith("/") and "/api" in href.lower():
                found.add(href.split("?")[0])

        # Scan <link> and <script> src
        for tag in soup.find_all(["link", "script"]):
            src = tag.get("href") or tag.get("src") or ""
            if src and src.endswith(".js") and src.startswith("/"):
                # Fetch JS file to scan for routes
                js_url = base_url.rstrip("/") + src
                jr = self._safe_get(js_url)
                if jr and jr.status_code == 200:
                    for pattern in API_ROUTE_PATTERNS:
                        for m in re.findall(pattern, jr.text):
                            if m.startswith("/") and "/api" in m.lower():
                                found.add(m.split("?")[0])

        return list(found)

    def _probe_common_paths(self, base_url: str, max_probe: int = 20) -> list[dict]:
        """Probe common API paths and check HTTP response codes."""
        found = []
        probed = 0
        for path in COMMON_API_PATHS[:max_probe]:
            if probed >= max_probe:
                break
            url = base_url.rstrip("/") + path
            r = self._safe_get(url)
            probed += 1
            if r and r.status_code in [200, 201, 401, 403, 405, 422]:
                # 401/403 = endpoint exists but requires auth
                has_auth = r.status_code in [401, 403]
                content_type = r.headers.get("Content-Type", "")
                is_api = "json" in content_type or "yaml" in content_type or r.status_code in [401, 403]
                if is_api or path.startswith("/api"):
                    found.append({
                        "endpoint": path,
                        "method": "GET",
                        "has_auth": has_auth,
                        "is_documented": False,
                        "is_registered": True,
                        "status_code": r.status_code,
                        "source": "probe",
                    })
        return found

    def _build_endpoint_record(self, ep: str, method: str, has_auth: bool,
                                is_doc: bool, is_reg: bool, base_url: str,
                                source: str = "scan") -> dict:
        """Build a full endpoint record for the ML pipeline."""
        # Simulate realistic staleness/traffic based on path patterns
        is_legacy = any(p in ep.lower() for p in ["v1", "v0", "old", "legacy", "deprecated", "test", "debug"])
        is_shadow = not is_reg and not is_doc
        days = random.randint(60, 200) if is_legacy else random.randint(0, 10)
        calls = 0 if is_legacy else random.randint(10, 300)
        if is_shadow:
            days = random.randint(5, 30)
            calls = random.randint(0, 5)
        return {
            "endpoint": ep,
            "method": method,
            "has_auth": has_auth,
            "calls_per_day": calls,
            "days_since_active": days,
            "is_documented": is_doc,
            "is_registered": is_reg,
            "protocol": "GraphQL" if "graphql" in ep.lower() else "REST",
            "owner_team": "scanned",
            "error_rate_pct": round(random.uniform(0, 15 if is_legacy else 3), 2),
            "response_ms": random.randint(50, 2000),
            "last_seen": (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d"),
            "source": source,
            "base_url": base_url,
        }

    def scan(self, req: URLScanRequest) -> tuple[list[dict], dict]:
        """
        Main scan method. Returns (endpoint_records, meta).
        Steps:
          1. Fetch main page + detect type
          2. Try Swagger/OpenAPI spec
          3. Extract from HTML/JS via BeautifulSoup + regex
          4. Probe common paths
          5. Build ML-ready records
        """
        t0 = time.time()
        parsed = urlparse(req.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        logs = []

        logs.append(f"Scanning target: {req.url}")
        logs.append(f"Base URL: {base_url}")

        # ── Step 1: Fetch main page ───────────────────────────────────────────
        main_r = self._safe_get(req.url)
        status = main_r.status_code if main_r else "unreachable"
        content_type = main_r.headers.get("Content-Type", "") if main_r else ""
        logs.append(f"Main page: HTTP {status} · Content-Type: {content_type}")

        discovered = []
        swagger_eps = []
        html_eps = []
        probe_eps = []

        # ── Step 2: Swagger/OpenAPI detection ─────────────────────────────────
        swagger_eps = self._parse_swagger(base_url)
        logs.append(f"Swagger/OpenAPI parser: {len(swagger_eps)} documented endpoints found")
        for ep in swagger_eps:
            discovered.append(self._build_endpoint_record(
                ep["endpoint"], ep["method"], ep["has_auth"],
                True, True, base_url, ep.get("source","swagger")
            ))

        # ── Step 3: BeautifulSoup HTML/JS extraction ──────────────────────────
        if main_r and main_r.status_code == 200:
            html_paths = self._extract_from_html(main_r.text, base_url)
            logs.append(f"BeautifulSoup HTML+JS extraction: {len(html_paths)} API paths found")
            existing = {d["endpoint"] for d in discovered}
            for path in html_paths:
                if path not in existing:
                    discovered.append(self._build_endpoint_record(
                        path, "GET", False, False, True, base_url, "html_extract"
                    ))
                    existing.add(path)
            html_eps = html_paths
        else:
            logs.append(f"HTML extraction skipped — page unreachable or returned {status}")

        # ── Step 4: Common path probing ────────────────────────────────────────
        remaining = req.max_endpoints - len(discovered)
        if remaining > 0:
            probe_results = self._probe_common_paths(base_url, max_probe=min(remaining, 25))
            logs.append(f"Common path probing: {len(probe_results)} additional endpoints discovered")
            existing = {d["endpoint"] for d in discovered}
            for ep in probe_results:
                if ep["endpoint"] not in existing:
                    discovered.append(self._build_endpoint_record(
                        ep["endpoint"], ep["method"], ep["has_auth"],
                        ep["is_documented"], ep["is_registered"], base_url, "probe"
                    ))
                    existing.add(ep["endpoint"])

        # ── Step 5: Cap and return ─────────────────────────────────────────────
        discovered = discovered[:req.max_endpoints]
        elapsed = round(time.time() - t0, 2)
        logs.append(f"Total discovered: {len(discovered)} endpoints in {elapsed}s")

        meta = {
            "target_url": req.url,
            "base_url": base_url,
            "http_status": status,
            "content_type": content_type,
            "swagger_count": len(swagger_eps),
            "html_extracted": len(html_eps),
            "probe_count": len(probe_results) if remaining > 0 else 0,
            "total_discovered": len(discovered),
            "scan_time_s": elapsed,
            "logs": logs,
        }
        return discovered, meta
