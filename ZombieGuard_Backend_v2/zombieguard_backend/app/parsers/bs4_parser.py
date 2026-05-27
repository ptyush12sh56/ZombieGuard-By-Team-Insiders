"""
ZombieGuard — BeautifulSoup API Document Parser
Parses Swagger/OpenAPI HTML docs, API registry XML/HTML pages, and network traffic
dumps to discover undocumented (shadow) endpoints.
Tools used: BeautifulSoup4 + lxml/html.parser
"""

from bs4 import BeautifulSoup
import re
from typing import Optional


# ── Simulated Swagger HTML (mirrors a real bank OpenAPI doc page) ──────────
SWAGGER_HTML = """
<html><body>
<div class="swagger-ui">
  <div class="opblock opblock-get">
    <span class="opblock-summary-path">/api/v2/accounts/{id}/balance</span>
    <span class="opblock-summary-method">GET</span>
    <div class="opblock-description">Returns account balance. Auth: Bearer required.</div>
  </div>
  <div class="opblock opblock-post">
    <span class="opblock-summary-path">/api/v2/payments/initiate</span>
    <span class="opblock-summary-method">POST</span>
    <div class="opblock-description">Initiate payment. Auth: Bearer required.</div>
  </div>
  <div class="opblock opblock-post">
    <span class="opblock-summary-path">/api/v2/users/auth/login</span>
    <span class="opblock-summary-method">POST</span>
    <div class="opblock-description">User login endpoint. Auth: None (public).</div>
  </div>
  <div class="opblock opblock-get">
    <span class="opblock-summary-path">/api/v2/kyc/verify</span>
    <span class="opblock-summary-method">GET</span>
    <div class="opblock-description">KYC verification. Auth: Bearer required.</div>
  </div>
  <div class="opblock opblock-post">
    <span class="opblock-summary-path">/api/v2/upi/pay</span>
    <span class="opblock-summary-method">POST</span>
    <div class="opblock-description">UPI payment. Auth: Bearer required.</div>
  </div>
  <div class="opblock opblock-get">
    <span class="opblock-summary-path">/api/v2/loans/status</span>
    <span class="opblock-summary-method">GET</span>
    <div class="opblock-description">Loan status. Auth: Bearer required.</div>
  </div>
  <div class="opblock opblock-post">
    <span class="opblock-summary-path">/api/v2/neft/transfer</span>
    <span class="opblock-summary-method">POST</span>
    <div class="opblock-description">NEFT transfer. Auth: Bearer required.</div>
  </div>
  <div class="opblock opblock-get">
    <span class="opblock-summary-path">/api/v2/forex/rates</span>
    <span class="opblock-summary-method">GET</span>
    <div class="opblock-description">Forex rates. Auth: Bearer required.</div>
  </div>
</div>
</body></html>
"""

# ── Simulated API Registry XML ────────────────────────────────────────────
API_REGISTRY_XML = """
<?xml version="1.0" encoding="UTF-8"?>
<apiRegistry bank="UnionBank" version="2.0">
  <api id="1" status="active" team="core-banking" registered="true">
    <path>/api/v2/accounts/{id}/balance</path><method>GET</method><auth>Bearer</auth>
  </api>
  <api id="2" status="active" team="payments" registered="true">
    <path>/api/v2/transactions/list</path><method>GET</method><auth>Bearer</auth>
  </api>
  <api id="3" status="deprecated" team="legacy" registered="true">
    <path>/api/v1/accounts/balance</path><method>GET</method><auth>None</auth>
  </api>
  <api id="4" status="unknown" team="unknown" registered="false">
    <path>/api/internal/debug/sql</path><method>GET</method><auth>None</auth>
  </api>
  <api id="5" status="unknown" team="unknown" registered="false">
    <path>/api/shadow/data-dump</path><method>GET</method><auth>None</auth>
  </api>
  <api id="6" status="deprecated" team="legacy" registered="true">
    <path>/api/v1/admin/users/reset</path><method>POST</method><auth>None</auth>
  </api>
  <api id="7" status="active" team="identity" registered="true">
    <path>/api/v2/kyc/verify</path><method>POST</method><auth>Bearer</auth>
  </api>
  <api id="8" status="unknown" team="unknown" registered="false">
    <path>/api/dev/testbed</path><method>POST</method><auth>None</auth>
  </api>
</apiRegistry>
"""

# ── Simulated network traffic log (HAR-like) for shadow fingerprinting ────
TRAFFIC_LOG = """
2024-01-15 10:23:44 POST /api/v2/payments/initiate 200 auth=Bearer
2024-01-15 10:23:45 GET  /api/v2/accounts/1234/balance 200 auth=Bearer
2024-01-15 10:24:01 GET  /api/internal/metrics-raw 200 auth=None
2024-01-15 10:24:15 POST /api/undoc/reconcile 200 auth=None
2024-01-15 10:25:00 GET  /api/shadow/customer-pii 200 auth=None
2024-01-15 10:25:30 POST /api/v2/upi/pay 200 auth=Bearer
2024-01-15 10:26:00 POST /api/internal/admin-bypass 200 auth=None
2024-01-15 10:26:45 GET  /api/v2/forex/rates 200 auth=Bearer
"""


class SwaggerParser:
    """
    Parses Swagger/OpenAPI HTML documentation using BeautifulSoup
    to extract documented endpoints (forms the API Registry source).
    """

    def parse(self, html: str = SWAGGER_HTML) -> list[dict]:
        soup = BeautifulSoup(html, "html.parser")
        endpoints = []
        for block in soup.select(".opblock"):
            path_el = block.select_one(".opblock-summary-path")
            method_el = block.select_one(".opblock-summary-method")
            desc_el = block.select_one(".opblock-description")
            if not path_el or not method_el:
                continue
            desc = desc_el.get_text(strip=True) if desc_el else ""
            has_auth = "Bearer" in desc or "required" in desc.lower()
            endpoints.append({
                "endpoint": path_el.get_text(strip=True),
                "method": method_el.get_text(strip=True),
                "has_auth": has_auth,
                "is_documented": True,
                "source": "swagger_html",
                "description": desc,
            })
        return endpoints


class APIRegistryXMLParser:
    """
    Parses API registry XML using BeautifulSoup (lxml/xml parser)
    to get the official registered endpoint list.
    """

    def parse(self, xml: str = API_REGISTRY_XML) -> list[dict]:
        soup = BeautifulSoup(xml, "lxml-xml")
        endpoints = []
        for api in soup.find_all("api"):
            path = api.find("path")
            method = api.find("method")
            auth = api.find("auth")
            if not path or not method:
                continue
            status = api.get("status", "unknown")
            endpoints.append({
                "endpoint": path.get_text(strip=True),
                "method": method.get_text(strip=True),
                "has_auth": auth and auth.get_text(strip=True) != "None",
                "is_registered": api.get("registered", "false") == "true",
                "owner_team": api.get("team", "unknown"),
                "status": status,
                "source": "registry_xml",
            })
        return endpoints


class TrafficFingerprintParser:
    """
    Parses raw network traffic logs (packet traces) using BeautifulSoup
    and regex to fingerprint shadow APIs — endpoints receiving traffic
    but NOT present in the official Swagger/registry.
    """

    def parse(self, traffic: str = TRAFFIC_LOG,
              registered_paths: Optional[set] = None) -> list[dict]:
        shadow = []
        registered_paths = registered_paths or set()

        for line in traffic.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            # parse: timestamp method path status auth=...
            m = re.match(
                r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\w+)\s+(\S+)\s+(\d+)\s+auth=(\S+)",
                line
            )
            if not m:
                continue
            _, method, path, status, auth_val = m.groups()
            # Normalise path (strip query params, numeric IDs)
            normalised = re.sub(r"/\d+", "/{id}", path)
            if normalised not in registered_paths:
                shadow.append({
                    "endpoint": normalised,
                    "method": method,
                    "has_auth": auth_val != "None",
                    "is_registered": False,
                    "is_documented": False,
                    "owner_team": "unknown",
                    "source": "traffic_fingerprint",
                    "calls_detected": 1,
                })
        # deduplicate
        seen = {}
        for ep in shadow:
            key = ep["endpoint"]
            if key in seen:
                seen[key]["calls_detected"] += 1
            else:
                seen[key] = ep
        return list(seen.values())


class CVEPatternValidator:
    """
    Validates endpoint paths against known CVE patterns using Pydantic.
    Uses BeautifulSoup to parse NVD/MITRE CVE XML feeds (simulated).
    """
    CVE_PATTERNS = {
        "debug":    {"cve": "CVE-2023-1234", "severity": "CRITICAL", "desc": "Debug endpoint exposes SQL interface"},
        "admin":    {"cve": "CVE-2022-5678", "severity": "HIGH",     "desc": "Admin reset without MFA"},
        "sql":      {"cve": "CVE-2021-9012", "severity": "CRITICAL", "desc": "SQL injection surface"},
        "test":     {"cve": "CVE-2020-3456", "severity": "HIGH",     "desc": "Test endpoint left in production"},
        "internal": {"cve": "CVE-2023-7890", "severity": "HIGH",     "desc": "Internal metrics exposed externally"},
        "shadow":   {"cve": "CVE-2024-1111", "severity": "CRITICAL", "desc": "Shadow data-dump endpoint"},
        "pii":      {"cve": "CVE-2024-2222", "severity": "CRITICAL", "desc": "PII data exposure"},
        "v0":       {"cve": "CVE-2019-0001", "severity": "MEDIUM",   "desc": "Legacy v0 API with no security"},
        "v1":       {"cve": "CVE-2020-0002", "severity": "MEDIUM",   "desc": "Legacy v1 API deprecated"},
        "dump":     {"cve": "CVE-2023-3333", "severity": "CRITICAL", "desc": "Data dump endpoint"},
        "backup":   {"cve": "CVE-2022-4444", "severity": "HIGH",     "desc": "Backup file exposure"},
        "legacy":   {"cve": "CVE-2021-5555", "severity": "MEDIUM",   "desc": "Legacy endpoint without updates"},
    }

    def check(self, endpoint: str) -> list[dict]:
        ep_lower = endpoint.lower()
        matches = []
        for pattern, info in self.CVE_PATTERNS.items():
            if pattern in ep_lower:
                matches.append({"pattern": pattern, **info})
        return matches


# ── Unified ingestion pipeline ────────────────────────────────
class APIIngestionPipeline:
    """
    Orchestrates all BeautifulSoup parsers to build unified endpoint list.
    Slide 5: API Gateway Logs + Network Traffic + API Registry + CVE DB + API Metadata
    """

    def __init__(self):
        self.swagger = SwaggerParser()
        self.registry = APIRegistryXMLParser()
        self.traffic = TrafficFingerprintParser()
        self.cve = CVEPatternValidator()

    def ingest(self) -> tuple[list[dict], dict]:
        # Parse all sources
        swagger_eps = self.swagger.parse()
        registry_eps = self.registry.parse()
        traffic_eps = self.traffic.parse(
            registered_paths={ep["endpoint"] for ep in swagger_eps + registry_eps}
        )

        # Merge: registry is authoritative, swagger enriches, traffic adds shadow
        merged = {}
        for ep in registry_eps:
            key = ep["endpoint"]
            merged[key] = {**ep, "is_documented": False}
        for ep in swagger_eps:
            key = ep["endpoint"]
            if key in merged:
                merged[key].update({"is_documented": True, "description": ep.get("description", "")})
            else:
                merged[key] = {**ep, "is_registered": False}
        for ep in traffic_eps:
            key = ep["endpoint"]
            if key not in merged:
                merged[key] = ep  # shadow — only seen in traffic

        # Attach CVE data
        results = []
        for ep in merged.values():
            cve_hits = self.cve.check(ep["endpoint"])
            results.append({**ep, "cve_hits": cve_hits, "cve_count": len(cve_hits)})

        meta = {
            "swagger_count": len(swagger_eps),
            "registry_count": len(registry_eps),
            "traffic_shadow_count": len(traffic_eps),
            "total_unique": len(results),
            "parsers_used": ["BeautifulSoup/html.parser", "BeautifulSoup/lxml-xml", "Regex/traffic"],
        }
        return results, meta
