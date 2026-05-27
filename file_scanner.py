"""
ZombieGuard — File Upload Scanner Service
Feature 2: Upload a file (CSV / JSON / TXT) containing multiple API endpoints
Supported formats:
  - CSV:  endpoint,method,has_auth,calls_per_day,days_since_active,...
  - JSON: [{"endpoint":"/api/v1/users","method":"GET",...}, ...]
  - TXT:  one URL/path per line  (e.g. https://example.com/api/v1/users)
  - YAML: OpenAPI/Swagger spec
Uses: Pydantic for validation, pandas for CSV parsing
"""

import io
import csv
import json
import re
import time
from datetime import datetime, timedelta
from typing import Optional
import random

from pydantic import BaseModel, field_validator


# ── Pydantic schema for one uploaded endpoint row ──────────────────────────────
class UploadedEndpoint(BaseModel):
    endpoint: str
    method: str = "GET"
    has_auth: bool = False
    calls_per_day: int = 0
    days_since_active: int = 0
    protocol: str = "REST"
    owner_team: str = "uploaded"
    is_documented: bool = False
    is_registered: bool = True
    error_rate_pct: float = 0.0
    response_ms: int = 200

    @field_validator("endpoint")
    @classmethod
    def normalise_endpoint(cls, v):
        v = v.strip()
        # If full URL, extract just the path
        if v.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            parsed = urlparse(v)
            v = parsed.path or "/"
        if not v.startswith("/"):
            v = "/" + v
        return v

    @field_validator("method")
    @classmethod
    def upper_method(cls, v):
        return v.strip().upper() if v else "GET"

    @field_validator("calls_per_day", "days_since_active", "response_ms")
    @classmethod
    def non_negative(cls, v):
        return max(0, int(v))

    @field_validator("error_rate_pct")
    @classmethod
    def clamp_err(cls, v):
        return max(0.0, min(100.0, float(v)))


SUPPORTED_EXTENSIONS = {".csv", ".json", ".txt", ".yaml", ".yml"}
MAX_FILE_SIZE_MB = 10
MAX_ROWS = 500

# ── CSV column aliases (flexible header matching) ─────────────────────────────
COL_ALIASES = {
    "endpoint":         ["endpoint", "path", "url", "api_path", "route", "api"],
    "method":           ["method", "http_method", "verb", "type"],
    "has_auth":         ["has_auth", "auth", "authenticated", "secure", "requires_auth"],
    "calls_per_day":    ["calls_per_day", "calls", "traffic", "requests", "hits", "daily_calls"],
    "days_since_active":["days_since_active", "days_inactive", "stale_days", "age", "last_active"],
    "protocol":         ["protocol", "proto", "api_type"],
    "owner_team":       ["owner_team", "team", "owner", "department", "service"],
    "is_documented":    ["is_documented", "documented", "in_swagger", "in_registry"],
    "is_registered":    ["is_registered", "registered", "in_registry", "known"],
    "error_rate_pct":   ["error_rate_pct", "error_rate", "errors", "failure_rate"],
    "response_ms":      ["response_ms", "latency", "response_time", "latency_ms"],
}

def _find_col(headers: list[str], field: str) -> Optional[str]:
    """Find a CSV column name matching a field, case-insensitive."""
    h_lower = {h.lower().strip(): h for h in headers}
    for alias in COL_ALIASES.get(field, [field]):
        if alias.lower() in h_lower:
            return h_lower[alias.lower()]
    return None

def _truthy(val: str) -> bool:
    return str(val).strip().lower() in ("1", "true", "yes", "y", "t", "on")


class FileScanner:
    """
    Parses uploaded files into ML-ready endpoint records.
    Supports: CSV, JSON, TXT (one per line), YAML (OpenAPI spec)
    """

    def parse_csv(self, content: str) -> tuple[list[dict], list[str]]:
        logs = []
        records = []
        reader = csv.DictReader(io.StringIO(content))
        headers = reader.fieldnames or []
        logs.append(f"CSV headers detected: {list(headers)}")

        # Build column map
        col_map = {f: _find_col(list(headers), f) for f in COL_ALIASES}
        ep_col = col_map.get("endpoint")
        if not ep_col:
            raise ValueError(f"No 'endpoint' column found. Headers: {list(headers)}. Expected one of: {COL_ALIASES['endpoint']}")

        skipped = 0
        for i, row in enumerate(reader):
            if i >= MAX_ROWS:
                logs.append(f"Row limit ({MAX_ROWS}) reached — truncating")
                break
            try:
                ep_val = row.get(ep_col, "").strip()
                if not ep_val:
                    skipped += 1
                    continue

                def get(field, default):
                    col = col_map.get(field)
                    return row.get(col, default) if col else default

                rec = UploadedEndpoint(
                    endpoint=ep_val,
                    method=get("method", "GET"),
                    has_auth=_truthy(get("has_auth", "false")),
                    calls_per_day=int(float(get("calls_per_day", 0) or 0)),
                    days_since_active=int(float(get("days_since_active", 0) or 0)),
                    protocol=get("protocol", "REST"),
                    owner_team=get("owner_team", "uploaded"),
                    is_documented=_truthy(get("is_documented", "false")),
                    is_registered=_truthy(get("is_registered", "true")),
                    error_rate_pct=float(get("error_rate_pct", 0.0) or 0.0),
                    response_ms=int(float(get("response_ms", 200) or 200)),
                )
                records.append(rec.model_dump())
            except Exception as e:
                skipped += 1
                logs.append(f"Row {i+2} skipped: {e}")

        logs.append(f"CSV parsed: {len(records)} valid rows, {skipped} skipped")
        return records, logs

    def parse_json(self, content: str) -> tuple[list[dict], list[str]]:
        logs = []
        records = []
        data = json.loads(content)

        # Support both list and {"apis": [...]} / {"endpoints": [...]} wrappers
        if isinstance(data, dict):
            for key in ["apis", "endpoints", "paths", "routes", "data", "items"]:
                if key in data and isinstance(data[key], list):
                    data = data[key]
                    break
            if isinstance(data, dict):
                raise ValueError("JSON must be a list of endpoint objects, or a dict with 'endpoints'/'apis' key")

        logs.append(f"JSON: {len(data)} items found")
        skipped = 0
        for i, item in enumerate(data[:MAX_ROWS]):
            try:
                if isinstance(item, str):
                    # plain URL strings
                    rec = UploadedEndpoint(endpoint=item)
                else:
                    # Find endpoint field
                    ep_val = None
                    for alias in COL_ALIASES["endpoint"]:
                        if alias in item:
                            ep_val = item[alias]
                            break
                    if not ep_val:
                        skipped += 1
                        continue

                    def getj(field, default):
                        for alias in COL_ALIASES.get(field, [field]):
                            if alias in item:
                                return item[alias]
                        return default

                    rec = UploadedEndpoint(
                        endpoint=ep_val,
                        method=getj("method", "GET"),
                        has_auth=bool(getj("has_auth", False)),
                        calls_per_day=int(float(getj("calls_per_day", 0) or 0)),
                        days_since_active=int(float(getj("days_since_active", 0) or 0)),
                        protocol=getj("protocol", "REST"),
                        owner_team=getj("owner_team", "uploaded"),
                        is_documented=bool(getj("is_documented", False)),
                        is_registered=bool(getj("is_registered", True)),
                        error_rate_pct=float(getj("error_rate_pct", 0.0) or 0.0),
                        response_ms=int(float(getj("response_ms", 200) or 200)),
                    )
                records.append(rec.model_dump())
            except Exception as e:
                skipped += 1
                logs.append(f"Item {i+1} skipped: {e}")

        logs.append(f"JSON parsed: {len(records)} valid, {skipped} skipped")
        return records, logs

    def parse_txt(self, content: str) -> tuple[list[dict], list[str]]:
        """One URL/path per line."""
        logs = []
        records = []
        skipped = 0
        lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
        logs.append(f"TXT: {len(lines)} non-empty lines")
        for i, line in enumerate(lines[:MAX_ROWS]):
            try:
                method = "GET"
                # Support "METHOD /path" format
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[0].upper() in ["GET","POST","PUT","PATCH","DELETE"]:
                    method, line = parts[0].upper(), parts[1]
                rec = UploadedEndpoint(endpoint=line, method=method)
                records.append(rec.model_dump())
            except Exception as e:
                skipped += 1
                logs.append(f"Line {i+1} skipped: {e}")
        logs.append(f"TXT parsed: {len(records)} valid, {skipped} skipped")
        return records, logs

    def parse_yaml_openapi(self, content: str) -> tuple[list[dict], list[str]]:
        """Parse OpenAPI/Swagger YAML spec."""
        logs = []
        records = []
        try:
            import yaml
            spec = yaml.safe_load(content)
        except ImportError:
            # Fallback: basic regex parsing without PyYAML
            logs.append("PyYAML not installed — using regex fallback for YAML")
            paths = re.findall(r'^\s{2}(/[^\s:]+):', content, re.MULTILINE)
            methods = re.findall(r'^\s{4}(get|post|put|patch|delete):', content, re.MULTILINE | re.IGNORECASE)
            for i, p in enumerate(paths[:MAX_ROWS]):
                method = methods[i].upper() if i < len(methods) else "GET"
                try:
                    rec = UploadedEndpoint(endpoint=p, method=method)
                    records.append(rec.model_dump())
                except Exception:
                    pass
            logs.append(f"YAML regex fallback: {len(records)} endpoints")
            return records, logs

        paths = spec.get("paths", {})
        base_path = spec.get("basePath", "")
        logs.append(f"OpenAPI/Swagger YAML: {len(paths)} paths in spec")
        for route, methods in paths.items():
            for method, info in methods.items():
                if not isinstance(info, dict):
                    continue
                if method.upper() not in ["GET","POST","PUT","PATCH","DELETE","HEAD"]:
                    continue
                security = info.get("security", spec.get("security", None))
                has_auth = security is not None and len(security) > 0
                try:
                    rec = UploadedEndpoint(
                        endpoint=base_path + route, method=method.upper(),
                        has_auth=has_auth, is_documented=True, is_registered=True,
                    )
                    records.append(rec.model_dump())
                except Exception:
                    pass
        logs.append(f"YAML parsed: {len(records)} endpoints from OpenAPI spec")
        return records, logs

    def parse(self, filename: str, content: bytes) -> tuple[list[dict], list[str]]:
        """Auto-detect format and parse."""
        # Size check
        size_mb = len(content) / (1024 * 1024)
        if size_mb > MAX_FILE_SIZE_MB:
            raise ValueError(f"File too large: {size_mb:.1f}MB (max {MAX_FILE_SIZE_MB}MB)")

        ext = "." + filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        text = content.decode("utf-8", errors="replace")
        logs = [f"File: {filename} ({size_mb:.2f}MB, format={ext or 'unknown'})"]

        if ext == ".csv":
            recs, parse_logs = self.parse_csv(text)
        elif ext == ".json":
            recs, parse_logs = self.parse_json(text)
        elif ext in (".yaml", ".yml"):
            recs, parse_logs = self.parse_yaml_openapi(text)
        elif ext == ".txt":
            recs, parse_logs = self.parse_txt(text)
        else:
            # Auto-detect by content
            stripped = text.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                recs, parse_logs = self.parse_json(text)
            elif "," in stripped.splitlines()[0] if stripped.splitlines() else False:
                recs, parse_logs = self.parse_csv(text)
            else:
                recs, parse_logs = self.parse_txt(text)

        logs.extend(parse_logs)
        # Enrich with last_seen
        now = datetime.now()
        for r in recs:
            if "last_seen" not in r or not r.get("last_seen"):
                r["last_seen"] = (now - timedelta(days=r["days_since_active"])).strftime("%Y-%m-%d")
        return recs, logs


# ── Sample files generator ─────────────────────────────────────────────────────
SAMPLE_CSV = """endpoint,method,has_auth,calls_per_day,days_since_active,protocol,owner_team
/api/v2/accounts/{id}/balance,GET,true,150,1,REST,core-banking
/api/v2/payments/initiate,POST,true,88,0,REST,payments
/api/v1/payment/test,POST,false,0,87,REST,legacy
/api/internal/debug/sql,GET,false,0,120,REST,unknown
/api/v1/admin/users/reset,POST,false,0,200,REST,unknown
/api/shadow/customer-pii,GET,false,2,8,REST,unknown
/api/v2/upi/pay,POST,true,180,0,REST,payments
/api/v0/accounts,GET,false,0,150,REST,legacy
/api/v2/kyc/verify,POST,true,75,0,REST,identity
/api/undoc/reconcile,POST,false,0,15,REST,unknown
"""

SAMPLE_JSON = json.dumps([
    {"endpoint": "/api/v2/accounts/{id}/balance", "method": "GET", "has_auth": True, "calls_per_day": 150, "days_since_active": 1},
    {"endpoint": "/api/v1/payment/test", "method": "POST", "has_auth": False, "calls_per_day": 0, "days_since_active": 87},
    {"endpoint": "/api/internal/debug/sql", "method": "GET", "has_auth": False, "calls_per_day": 0, "days_since_active": 120},
    {"endpoint": "/api/shadow/customer-pii", "method": "GET", "has_auth": False, "calls_per_day": 2, "days_since_active": 8},
    {"endpoint": "/api/v2/upi/pay", "method": "POST", "has_auth": True, "calls_per_day": 180, "days_since_active": 0},
], indent=2)

SAMPLE_TXT = """/api/v2/accounts/{id}/balance
POST /api/v2/payments/initiate
GET /api/v1/payment/test
GET /api/internal/debug/sql
POST /api/v1/admin/users/reset
GET /api/shadow/customer-pii
POST /api/v2/upi/pay
GET /api/v0/accounts
"""
