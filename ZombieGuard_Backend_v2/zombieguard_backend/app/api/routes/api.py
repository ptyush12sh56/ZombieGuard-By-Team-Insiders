"""
ZombieGuard — FastAPI Routes
All endpoints use Pydantic request/response validation.
"""
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime
from typing import Optional
import random

from ...db.session import get_db
from ...db.models import (APIEndpoint, RiskScore, AuditLog, DefenceAction,
                          Alert, ScanSession, CVEMatch)
from ...schemas.schemas import ScanRequest, DefenceActionCreate, RiskCalcRequest, RiskCalcResponse
from ...services.scan_service import run_full_scan
from ...ml.detector import CVSSRiskScorer, CVE_PATTERNS
from ...core.kafka_bus import get_broker
from ...parsers.bs4_parser import APIIngestionPipeline, CVEPatternValidator

router = APIRouter(prefix="/api", tags=["ZombieGuard"])
scorer = CVSSRiskScorer()


# ═══ SCAN ════════════════════════════════════════════════════════════════════
@router.post("/scan")
def trigger_scan(req: ScanRequest, db: Session = Depends(get_db)):
    """Full 5-step pipeline: BeautifulSoup → Kafka → IsolationForest+LSTM → CVSS → SQL Alchemy"""
    result = run_full_scan(db, req)
    return {"status": "success", "data": result}


# ═══ DASHBOARD ═══════════════════════════════════════════════════════════════
@router.get("/dashboard")
def get_dashboard(db: Session = Depends(get_db)):
    total = db.query(APIEndpoint).count()
    if total == 0:
        return {"status": "no_data", "message": "Run a scan first"}

    subq = (db.query(RiskScore.endpoint_id, func.max(RiskScore.id).label("mid"))
              .group_by(RiskScore.endpoint_id).subquery())
    latest = (db.query(RiskScore).join(subq, RiskScore.id == subq.c.mid).all())

    cls_counts = {}
    scores = []
    for rs in latest:
        cls_counts[rs.classification] = cls_counts.get(rs.classification, 0) + 1
        scores.append(rs.score)

    disabled  = db.query(DefenceAction).filter(DefenceAction.action_type == "disable").count()
    no_auth   = db.query(APIEndpoint).filter(APIEndpoint.has_auth == False).count()
    zombie_n  = cls_counts.get("ZOMBIE", 0)
    shadow_n  = cls_counts.get("SHADOW", 0)
    last_sess = db.query(ScanSession).order_by(desc(ScanSession.id)).first()

    return {"status": "ok", "data": {
        "total_apis":     total,
        "zombie":         zombie_n,
        "shadow":         shadow_n,
        "deprecated":     cls_counts.get("DEPRECATED", 0),
        "active":         cls_counts.get("ACTIVE", 0),
        "disabled":       disabled,
        "alert_count":    db.query(Alert).count(),
        "critical_count": db.query(Alert).filter(Alert.severity == "CRITICAL").count(),
        "high_count":     db.query(Alert).filter(Alert.severity == "HIGH").count(),
        "avg_risk_score": round(sum(scores) / len(scores), 1) if scores else 0,
        "owasp_api3":     zombie_n,
        "owasp_api7":     no_auth,
        "owasp_api9":     zombie_n + shadow_n,
        "owasp_api1":     db.query(RiskScore).filter(RiskScore.score > 70).count(),
        "last_scan":      last_sess.completed_at.isoformat() if last_sess and last_sess.completed_at else None,
        "scan_duration_s": last_sess.scan_duration_s if last_sess else 0,
    }}


# ═══ ENDPOINTS / INVENTORY ════════════════════════════════════════════════════
@router.get("/endpoints")
def get_endpoints(
    classification: Optional[str] = None,
    min_risk: Optional[float] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    subq = (db.query(RiskScore.endpoint_id, func.max(RiskScore.id).label("mid"))
              .group_by(RiskScore.endpoint_id).subquery())
    q = (db.query(APIEndpoint, RiskScore)
           .join(subq, APIEndpoint.id == subq.c.endpoint_id)
           .join(RiskScore, RiskScore.id == subq.c.mid))
    if classification:
        q = q.filter(RiskScore.classification == classification.upper())
    if min_risk is not None:
        q = q.filter(RiskScore.score >= min_risk)
    if search:
        q = q.filter(APIEndpoint.endpoint.ilike(f"%{search}%"))

    total = q.count()
    rows  = q.order_by(desc(RiskScore.score)).offset((page - 1) * page_size).limit(page_size).all()

    disabled_set = {d.endpoint for d in db.query(DefenceAction.endpoint)
                                           .filter(DefenceAction.action_type == "disable").all()}

    items = [{
        "id": ep.id, "endpoint": ep.endpoint, "method": ep.method,
        "has_auth": ep.has_auth, "calls_per_day": ep.calls_per_day,
        "days_since_active": ep.days_since_active, "last_seen": ep.last_seen,
        "protocol": ep.protocol, "owner_team": ep.owner_team,
        "error_rate_pct": ep.error_rate_pct, "response_ms": ep.response_ms,
        "is_documented": ep.is_documented, "is_registered": ep.is_registered,
        "risk_score": rs.score, "classification": rs.classification,
        "risk_reason": rs.risk_reason, "ml_anomaly": rs.ml_anomaly,
        "is_disabled": ep.endpoint in disabled_set,
    } for ep, rs in rows]
    return {"status": "ok", "total": total, "page": page, "page_size": page_size, "data": items}


@router.get("/endpoints/top-risky")
def top_risky(n: int = Query(10, ge=1, le=50), db: Session = Depends(get_db)):
    subq = (db.query(RiskScore.endpoint_id, func.max(RiskScore.id).label("mid"))
              .group_by(RiskScore.endpoint_id).subquery())
    rows = (db.query(APIEndpoint, RiskScore)
              .join(subq, APIEndpoint.id == subq.c.endpoint_id)
              .join(RiskScore, RiskScore.id == subq.c.mid)
              .order_by(desc(RiskScore.score)).limit(n).all())
    return {"status": "ok", "data": [
        {"endpoint": ep.endpoint, "method": ep.method, "risk_score": rs.score,
         "classification": rs.classification, "risk_reason": rs.risk_reason}
        for ep, rs in rows
    ]}


@router.get("/endpoints/distribution")
def distribution(db: Session = Depends(get_db)):
    subq = (db.query(RiskScore.endpoint_id, func.max(RiskScore.id).label("mid"))
              .group_by(RiskScore.endpoint_id).subquery())
    all_scores = [rs.score for _, rs in (
        db.query(APIEndpoint, RiskScore)
          .join(subq, APIEndpoint.id == subq.c.endpoint_id)
          .join(RiskScore, RiskScore.id == subq.c.mid).all())]
    bins = [0] * 5
    for s in all_scores:
        bins[min(int(s // 20), 4)] += 1
    return {"status": "ok", "data": {"bins": bins, "labels": ["0-20","21-40","41-60","61-80","81-100"]}}


# ═══ ALERTS ══════════════════════════════════════════════════════════════════
@router.get("/alerts")
def get_alerts(
    severity: Optional[str] = None,
    page: int = 1, page_size: int = 50,
    db: Session = Depends(get_db)
):
    q = db.query(Alert)
    if severity:
        q = q.filter(Alert.severity == severity.upper())
    total  = q.count()
    alerts = q.order_by(desc(Alert.risk_score)).offset((page-1)*page_size).limit(page_size).all()
    return {"status": "ok", "total": total, "data": [
        {"id": a.id, "severity": a.severity, "endpoint": a.endpoint,
         "risk_score": a.risk_score, "reason": a.reason,
         "channel": a.channel, "dispatched": a.dispatched,
         "timestamp": a.timestamp.isoformat()}
        for a in alerts
    ]}


# ═══ DEFENCE ═════════════════════════════════════════════════════════════════
@router.get("/defence")
def get_defence(db: Session = Depends(get_db)):
    actions = db.query(DefenceAction).order_by(desc(DefenceAction.id)).limit(100).all()
    return {"status": "ok", "data": [
        {"id": d.id, "action_type": d.action_type, "endpoint": d.endpoint,
         "risk_score": d.risk_score, "is_auto": d.is_auto,
         "triggered_by": d.triggered_by, "timestamp": d.timestamp.isoformat()}
        for d in actions
    ]}


@router.post("/defence")
def post_defence(req: DefenceActionCreate, db: Session = Depends(get_db)):
    valid = {"disable", "rotate", "whitelist", "alert", "enable"}
    if req.action_type not in valid:
        raise HTTPException(400, f"action_type must be one of {valid}")
    db.add(DefenceAction(
        action_type=req.action_type, endpoint=req.endpoint,
        risk_score=0.0, is_auto=False, triggered_by=req.actor or "manual"
    ))
    db.add(AuditLog(
        action=req.action_type.upper(), endpoint=req.endpoint,
        actor=req.actor or "manual", result="SUCCESS",
        notes=req.notes or f"Manual {req.action_type} via FastAPI"
    ))
    if req.action_type == "alert":
        db.add(Alert(severity="HIGH", endpoint=req.endpoint, risk_score=0.0,
                     reason="Manual alert triggered", channel="slack", dispatched=True))
    db.commit()
    get_broker().produce("defence-actions", req.endpoint,
                         {"action": req.action_type, "endpoint": req.endpoint, "manual": True})
    return {"status": "success", "message": f"'{req.action_type}' executed on {req.endpoint}"}


# ═══ AUDIT ═══════════════════════════════════════════════════════════════════
@router.get("/audit")
def get_audit(page: int = 1, page_size: int = 50, db: Session = Depends(get_db)):
    total = db.query(AuditLog).count()
    logs  = db.query(AuditLog).order_by(desc(AuditLog.id)).offset((page-1)*page_size).limit(page_size).all()
    return {"status": "ok", "total": total, "data": [
        {"id": l.id, "action": l.action, "endpoint": l.endpoint,
         "actor": l.actor, "result": l.result, "notes": l.notes,
         "timestamp": l.timestamp.isoformat()}
        for l in logs
    ]}


# ═══ RISK CALCULATOR ══════════════════════════════════════════════════════════
@router.post("/risk-calc", response_model=RiskCalcResponse)
def calc_risk(req: RiskCalcRequest):
    """Pydantic-validated CVSS risk calculator using NumPy scorer."""
    score, reason, breakdown = scorer.score_single(
        req.endpoint, req.has_auth, req.calls_per_day,
        req.days_since_active, req.is_documented
    )
    if score >= 80:   cls, verdict = "CRITICAL", "CRITICAL — Auto-disable triggered in <3 sec"
    elif score >= 60: cls, verdict = "HIGH",     "HIGH — SecOps alert dispatched"
    elif score >= 40: cls, verdict = "MEDIUM",   "MEDIUM — Monitoring elevated"
    else:             cls, verdict = "LOW",       "LOW — Normal monitoring"
    return RiskCalcResponse(score=score, classification=cls, verdict=verdict,
                            reason=reason, breakdown=breakdown)


# ═══ KAFKA STATUS ════════════════════════════════════════════════════════════
@router.get("/kafka-status")
def kafka_status():
    stats = get_broker().get_stats()
    return {"status": "ok", "data": stats}


@router.get("/kafka-events")
def kafka_events(topic: str = "api-gateway-logs", n: int = Query(20, le=100)):
    msgs = get_broker().consume(topic, max_msgs=n)
    return {"status": "ok", "topic": topic, "data": [
        {"key": m.key, "value": m.value, "timestamp": m.timestamp, "offset": m.offset}
        for m in msgs
    ]}


# ═══ BEAUTIFULSOUP PARSER STATUS ══════════════════════════════════════════════
@router.get("/parser-status")
def parser_status():
    """Show BeautifulSoup ingestion pipeline results."""
    pl = APIIngestionPipeline()
    eps, meta = pl.ingest()
    return {"status": "ok", "data": {
        "parsers": meta["parsers_used"],
        "swagger_endpoints": meta["swagger_count"],
        "registry_endpoints": meta["registry_count"],
        "shadow_traffic_endpoints": meta["traffic_shadow_count"],
        "total_discovered": meta["total_unique"],
        "sample": eps[:5],
    }}


# ═══ CVE DATABASE ════════════════════════════════════════════════════════════
@router.get("/cve-database")
def cve_database(db: Session = Depends(get_db)):
    """CVE patterns loaded from NVD/MITRE via Pydantic-validated feed."""
    matches = db.query(CVEMatch).limit(100).all()
    return {"status": "ok", "data": {
        "patterns_loaded": len(CVE_PATTERNS),
        "pattern_list": [
            {"pattern": p, "cve": w["cve"], "severity": w["severity"]}
            for p, w in CVE_PATTERNS.items()
        ],
        "db_matches": len(matches),
        "recent_matches": [
            {"endpoint_id": m.endpoint_id, "pattern": m.cve_pattern, "severity": m.severity}
            for m in matches[:20]
        ],
    }}


# ═══ DB STATS ════════════════════════════════════════════════════════════════
@router.get("/db-stats")
def db_stats(db: Session = Depends(get_db)):
    return {"status": "ok", "data": {
        "api_endpoints":     db.query(APIEndpoint).count(),
        "risk_scores":       db.query(RiskScore).count(),
        "audit_log_entries": db.query(AuditLog).count(),
        "cve_matches":       db.query(CVEMatch).count(),
        "defence_actions":   db.query(DefenceAction).count(),
        "alerts":            db.query(Alert).count(),
        "scan_sessions":     db.query(ScanSession).count(),
    }}


# ═══ SESSIONS ════════════════════════════════════════════════════════════════
@router.get("/sessions")
def sessions(db: Session = Depends(get_db)):
    rows = db.query(ScanSession).order_by(desc(ScanSession.id)).limit(20).all()
    return {"status": "ok", "data": [
        {"id": s.id, "total_apis": s.total_apis, "zombie": s.zombie_count,
         "shadow": s.shadow_count, "disabled": s.disabled_count,
         "alerts": s.alert_count, "duration_s": s.scan_duration_s,
         "started_at": s.started_at.isoformat(),
         "completed_at": s.completed_at.isoformat() if s.completed_at else None}
        for s in rows
    ]}


# ═══ ML METADATA ═════════════════════════════════════════════════════════════
@router.get("/ml-info")
def ml_info():
    return {"status": "ok", "data": {
        "models": [
            {"name": "IsolationForest", "library": "scikit-learn",
             "params": {"n_estimators": 200, "contamination": "tunable", "random_state": 42},
             "use": "Unsupervised anomaly detection — no labels needed"},
            {"name": "LSTM", "library": "TensorFlow/Keras (simulated)",
             "params": {"window": 30, "threshold": "85th percentile"},
             "use": "Temporal call-frequency sequence anomaly"},
            {"name": "CVSSRiskScorer", "library": "NumPy",
             "params": {"max_score": 100, "components": 5},
             "use": "Vectorised 0-100 CVSS-aligned risk scoring"},
        ],
        "features": ["calls_per_day","days_since_active","error_rate_pct",
                     "has_auth","is_documented","is_registered","response_ms"],
        "validation": "Pydantic v2 — field-level validators on all inputs",
        "storage": "SQL Alchemy + SQLite — all scores + audit trails persisted",
    }}


# ═══ FEATURE 1: URL / API LINK SCANNER ═══════════════════════════════════════
from fastapi import UploadFile, File, Form
from ...services.url_scanner import URLAPIScanner, URLScanRequest
from ...services.file_scanner import FileScanner, SAMPLE_CSV, SAMPLE_JSON, SAMPLE_TXT


@router.post("/scan/url", summary="Scan a website URL or API base URL for zombie endpoints")
def scan_url(req: URLScanRequest, db: Session = Depends(get_db)):
    """
    Feature 1: Provide any website URL or API base link.
    ZombieGuard will:
      1. Fetch the page + JS files (BeautifulSoup)
      2. Try Swagger/OpenAPI spec paths
      3. Probe common API path patterns
      4. Run full Isolation Forest + CVSS pipeline on discovered endpoints
    """
    from ...services.scan_service import run_full_scan
    from ...schemas.schemas import ScanRequest

    # Step 1 — discover endpoints from the URL
    scanner = URLAPIScanner(timeout=8)
    try:
        raw_data, url_meta = scanner.scan(req)
    except Exception as e:
        raise HTTPException(400, f"URL scan failed: {str(e)}")

    if not raw_data:
        return {
            "status": "no_endpoints",
            "message": f"No API endpoints discovered at {req.url}. Try a URL with a Swagger UI or API routes.",
            "url_meta": url_meta,
        }

    # Step 2 — run ML pipeline on discovered endpoints
    from ...ml.detector import ZombieDetector, CVSSRiskScorer
    from ...core.kafka_bus import get_broker, KafkaPipeline

    started = datetime.utcnow()
    detector = ZombieDetector(
        contamination=req.contamination,
        staleness_days=req.staleness_days
    )
    results, ml_meta = detector.fit_predict(raw_data)

    # Step 3 — persist to DB — clear ALL previous to avoid UNIQUE constraint
    db.query(RiskScore).delete()
    db.query(CVEMatch).delete()
    db.query(DefenceAction).filter(DefenceAction.action_type == "disable").delete()
    db.query(Alert).delete()
    db.query(APIEndpoint).delete()
    db.commit()

    broker = get_broker()
    kafka = KafkaPipeline(broker)
    disabled_eps, alert_count = [], 0

    for r in results:
        ep_obj = APIEndpoint(
            endpoint=r["endpoint"], method=r["method"],
            has_auth=r["has_auth"], calls_per_day=r["calls_per_day"],
            days_since_active=r["days_since_active"], last_seen=r.get("last_seen"),
            protocol=r["protocol"], owner_team="scanned",
            is_documented=r["is_documented"], is_registered=r["is_registered"],
            error_rate_pct=r["error_rate_pct"], response_ms=r["response_ms"],
        )
        db.add(ep_obj)
        db.flush()
        db.add(RiskScore(
            endpoint_id=ep_obj.id, score=r["risk_score"],
            classification=r["classification"], risk_reason=r["risk_reason"],
            ml_anomaly=r["ml_anomaly"],
        ))
        kafka.publish_ml_result(r["endpoint"], r["risk_score"], r["classification"])

        if req.auto_disable and r["risk_score"] >= 80:
            db.add(DefenceAction(
                action_type="disable", endpoint=r["endpoint"],
                risk_score=r["risk_score"], is_auto=True,
                triggered_by="ZombieGuard-AutoBot"
            ))
            db.add(AuditLog(
                action="DISABLE", endpoint=r["endpoint"],
                actor="ZombieGuard-AutoBot", result="SUCCESS",
                notes=f"URL scan: {req.url} · risk={r['risk_score']}"
            ))
            disabled_eps.append(r["endpoint"])

        if req.fire_webhook and r["risk_score"] >= 60:
            sev = "CRITICAL" if r["risk_score"] >= 80 else "HIGH"
            db.add(Alert(
                severity=sev, endpoint=r["endpoint"],
                risk_score=r["risk_score"], reason=r["risk_reason"],
                channel="slack+email", dispatched=True
            ))
            alert_count += 1

    cls_map = {}
    for r in results:
        cls_map[r["classification"]] = cls_map.get(r["classification"], 0) + 1

    completed = datetime.utcnow()
    session = ScanSession(
        total_apis=len(results),
        zombie_count=cls_map.get("ZOMBIE", 0),
        shadow_count=cls_map.get("SHADOW", 0),
        deprecated_count=cls_map.get("DEPRECATED", 0),
        active_count=cls_map.get("ACTIVE", 0),
        disabled_count=len(disabled_eps),
        alert_count=alert_count,
        contamination=req.contamination,
        staleness_days=req.staleness_days,
        scan_duration_s=round((completed - started).total_seconds(), 3),
        started_at=started,
        completed_at=completed,
    )
    db.add(session)
    db.commit()

    return {
        "status": "success",
        "data": {
            "session_id": session.id,
            "target_url": req.url,
            "total_apis": len(results),
            "zombie": cls_map.get("ZOMBIE", 0),
            "shadow": cls_map.get("SHADOW", 0),
            "deprecated": cls_map.get("DEPRECATED", 0),
            "active": cls_map.get("ACTIVE", 0),
            "disabled": len(disabled_eps),
            "alerts": alert_count,
            "ml_meta": ml_meta,
            "url_meta": url_meta,
            "scan_duration_s": session.scan_duration_s,
            "results_preview": [
                {"endpoint": r["endpoint"], "classification": r["classification"],
                 "risk_score": r["risk_score"], "risk_reason": r["risk_reason"]}
                for r in sorted(results, key=lambda x: -x["risk_score"])[:10]
            ],
        },
    }


# ═══ FEATURE 2: FILE UPLOAD SCANNER ═══════════════════════════════════════════
@router.post("/scan/upload", summary="Upload CSV/JSON/TXT/YAML file of API endpoints to scan")
async def scan_upload(
    file: UploadFile = File(...),
    contamination: float = Form(0.15),
    staleness_days: int = Form(30),
    auto_disable: bool = Form(True),
    rotate_keys: bool = Form(True),
    fire_webhook: bool = Form(True),
    db: Session = Depends(get_db),
):
    """
    Feature 2: Upload a file containing API endpoints.
    Supported formats:
      - CSV  — endpoint,method,has_auth,calls_per_day,days_since_active,...
      - JSON — [{"endpoint":"/api/v1/users","method":"GET",...}]
      - TXT  — one URL/path per line, optional METHOD prefix
      - YAML — OpenAPI/Swagger spec
    Runs full ML pipeline on parsed endpoints.
    """
    # Read + parse file
    content = await file.read()
    fs = FileScanner()
    try:
        raw_data, parse_logs = fs.parse(file.filename or "upload.txt", content)
    except Exception as e:
        raise HTTPException(400, f"File parse failed: {str(e)}")

    if not raw_data:
        return {
            "status": "no_endpoints",
            "message": "No valid endpoints found in uploaded file.",
            "parse_logs": parse_logs,
        }

    # Run ML pipeline
    from ...ml.detector import ZombieDetector
    from ...core.kafka_bus import get_broker, KafkaPipeline

    started = datetime.utcnow()
    detector = ZombieDetector(contamination=contamination, staleness_days=staleness_days)
    results, ml_meta = detector.fit_predict(raw_data)

    # Persist — clear ALL previous results to avoid UNIQUE constraint on endpoint
    db.query(RiskScore).delete()
    db.query(CVEMatch).delete()
    db.query(DefenceAction).filter(DefenceAction.action_type == "disable").delete()
    db.query(Alert).delete()
    db.query(APIEndpoint).delete()
    db.commit()

    broker = get_broker()
    kafka = KafkaPipeline(broker)
    disabled_eps, alert_count = [], 0

    for r in results:
        ep_obj = APIEndpoint(
            endpoint=r["endpoint"], method=r["method"],
            has_auth=r["has_auth"], calls_per_day=r["calls_per_day"],
            days_since_active=r["days_since_active"], last_seen=r.get("last_seen"),
            protocol=r["protocol"], owner_team="uploaded",
            is_documented=r["is_documented"], is_registered=r["is_registered"],
            error_rate_pct=r["error_rate_pct"], response_ms=r["response_ms"],
        )
        db.add(ep_obj)
        db.flush()
        db.add(RiskScore(
            endpoint_id=ep_obj.id, score=r["risk_score"],
            classification=r["classification"], risk_reason=r["risk_reason"],
            ml_anomaly=r["ml_anomaly"],
        ))
        kafka.publish_ml_result(r["endpoint"], r["risk_score"], r["classification"])

        if auto_disable and r["risk_score"] >= 80:
            db.add(DefenceAction(
                action_type="disable", endpoint=r["endpoint"],
                risk_score=r["risk_score"], is_auto=True,
                triggered_by="ZombieGuard-AutoBot"
            ))
            db.add(AuditLog(
                action="DISABLE", endpoint=r["endpoint"],
                actor="ZombieGuard-AutoBot", result="SUCCESS",
                notes=f"File upload scan: {file.filename} · risk={r['risk_score']}"
            ))
            disabled_eps.append(r["endpoint"])

        if fire_webhook and r["risk_score"] >= 60:
            sev = "CRITICAL" if r["risk_score"] >= 80 else "HIGH"
            db.add(Alert(
                severity=sev, endpoint=r["endpoint"],
                risk_score=r["risk_score"], reason=r["risk_reason"],
                channel="slack+email", dispatched=True
            ))
            alert_count += 1

    cls_map = {}
    for r in results:
        cls_map[r["classification"]] = cls_map.get(r["classification"], 0) + 1

    completed = datetime.utcnow()
    session = ScanSession(
        total_apis=len(results),
        zombie_count=cls_map.get("ZOMBIE", 0),
        shadow_count=cls_map.get("SHADOW", 0),
        deprecated_count=cls_map.get("DEPRECATED", 0),
        active_count=cls_map.get("ACTIVE", 0),
        disabled_count=len(disabled_eps),
        alert_count=alert_count,
        contamination=contamination,
        staleness_days=staleness_days,
        scan_duration_s=round((completed - started).total_seconds(), 3),
        started_at=started,
        completed_at=completed,
    )
    db.add(session)
    db.commit()
    db.add(AuditLog(
        action="FILE_UPLOAD_SCAN", endpoint=file.filename or "upload",
        actor="User", result="SUCCESS",
        notes=f"Parsed {len(raw_data)} records, {len(results)} scanned"
    ))
    db.commit()

    return {
        "status": "success",
        "data": {
            "session_id": session.id,
            "filename": file.filename,
            "total_parsed": len(raw_data),
            "total_scanned": len(results),
            "zombie": cls_map.get("ZOMBIE", 0),
            "shadow": cls_map.get("SHADOW", 0),
            "deprecated": cls_map.get("DEPRECATED", 0),
            "active": cls_map.get("ACTIVE", 0),
            "disabled": len(disabled_eps),
            "alerts": alert_count,
            "ml_meta": ml_meta,
            "parse_logs": parse_logs,
            "scan_duration_s": session.scan_duration_s,
            "results_preview": [
                {"endpoint": r["endpoint"], "classification": r["classification"],
                 "risk_score": r["risk_score"], "risk_reason": r["risk_reason"]}
                for r in sorted(results, key=lambda x: -x["risk_score"])[:10]
            ],
        },
    }


@router.get("/scan/sample-files", summary="Download sample files for testing upload scanner")
def get_sample_files(fmt: str = "csv"):
    """Returns sample file content for testing the upload feature."""
    from fastapi.responses import PlainTextResponse
    samples = {"csv": (SAMPLE_CSV, "text/csv"), "json": (SAMPLE_JSON, "application/json"), "txt": (SAMPLE_TXT, "text/plain")}
    content, media_type = samples.get(fmt, (SAMPLE_CSV, "text/csv"))
    return PlainTextResponse(content=content, media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename=sample_endpoints.{fmt}"})
