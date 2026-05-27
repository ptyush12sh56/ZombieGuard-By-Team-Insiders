"""
ZombieGuard — Pydantic Schemas (validation for all API request/response bodies)
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


# ── API Endpoint ──────────────────────────────────────────────────────────────
class APIEndpointBase(BaseModel):
    endpoint: str
    method: str = "GET"
    has_auth: bool = True
    calls_per_day: int = 0
    days_since_active: int = 0
    last_seen: Optional[str] = None
    protocol: str = "REST"
    owner_team: str = "unknown"
    is_documented: bool = True
    is_registered: bool = True
    error_rate_pct: float = 0.0
    response_ms: int = 200


class APIEndpointCreate(APIEndpointBase):
    pass


class APIEndpointOut(APIEndpointBase):
    id: int
    created_at: datetime
    # joined from risk_scores
    risk_score: Optional[float] = None
    classification: Optional[str] = None
    risk_reason: Optional[str] = None

    class Config:
        from_attributes = True


# ── Risk Score ────────────────────────────────────────────────────────────────
class RiskScoreOut(BaseModel):
    id: int
    endpoint_id: int
    score: float
    classification: str
    risk_reason: str
    ml_anomaly: int
    scanned_at: datetime

    class Config:
        from_attributes = True


# ── Audit Log ─────────────────────────────────────────────────────────────────
class AuditLogOut(BaseModel):
    id: int
    action: str
    endpoint: str
    actor: str
    result: str
    notes: str
    timestamp: datetime

    class Config:
        from_attributes = True


# ── Defence Action ────────────────────────────────────────────────────────────
class DefenceActionCreate(BaseModel):
    action_type: str   # disable / rotate / whitelist / alert
    endpoint: str
    actor: str = "manual"
    notes: str = ""


class DefenceActionOut(BaseModel):
    id: int
    action_type: str
    endpoint: str
    risk_score: float
    is_auto: bool
    triggered_by: str
    timestamp: datetime

    class Config:
        from_attributes = True


# ── Alert ─────────────────────────────────────────────────────────────────────
class AlertOut(BaseModel):
    id: int
    severity: str
    endpoint: str
    risk_score: float
    reason: str
    channel: str
    dispatched: bool
    timestamp: datetime

    class Config:
        from_attributes = True


# ── Scan ──────────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    contamination: float = Field(0.15, ge=0.05, le=0.40)
    staleness_days: int = Field(30, ge=7, le=90)
    auto_disable: bool = True
    rotate_keys: bool = True
    fire_webhook: bool = True
    deep_shadow: bool = False
    data_source: str = "synthetic"


class ScanSessionOut(BaseModel):
    id: int
    total_apis: int
    zombie_count: int
    shadow_count: int
    deprecated_count: int
    active_count: int
    disabled_count: int
    alert_count: int
    contamination: float
    staleness_days: int
    scan_duration_s: float
    started_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


# ── Dashboard ─────────────────────────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_apis: int
    zombie: int
    shadow: int
    deprecated: int
    active: int
    disabled: int
    alert_count: int
    critical_count: int
    high_count: int
    avg_risk_score: float
    owasp_api3: int
    owasp_api7: int
    owasp_api9: int
    owasp_api1: int
    last_scan: Optional[str]


# ── Risk Calculator ───────────────────────────────────────────────────────────
class RiskCalcRequest(BaseModel):
    endpoint: str
    days_since_active: int = 0
    calls_per_day: int = 0
    has_auth: bool = True
    is_documented: bool = True


class RiskCalcResponse(BaseModel):
    score: float
    classification: str
    verdict: str
    reason: str
    breakdown: dict
