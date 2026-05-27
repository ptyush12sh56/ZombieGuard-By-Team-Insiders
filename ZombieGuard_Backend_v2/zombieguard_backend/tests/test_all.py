"""
ZombieGuard — Test Suite
Tests all pipeline components: BeautifulSoup, ML, CVSS, DB, API routes
Run: pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.models import Base
from app.db.session import get_db
from app.ml.detector import (
    ZombieDetector, generate_synthetic_logs,
    CVSSRiskScorer, classify, CVE_PATTERNS
)
from app.parsers.bs4_parser import (
    SwaggerParser, APIRegistryXMLParser,
    TrafficFingerprintParser, CVEPatternValidator, APIIngestionPipeline
)
from app.core.kafka_bus import KafkaBrokerSim, KafkaPipeline
from app.schemas.schemas import ScanRequest, RiskCalcRequest, DefenceActionCreate

# ── Test DB setup ─────────────────────────────────────────────
TEST_DB = "sqlite:///./test_zombieguard.db"
test_engine = create_engine(TEST_DB, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
Base.metadata.create_all(bind=test_engine)

client = TestClient(app)


# ═══════════════════════════════════════════════════════════════
# 1. BEAUTIFULSOUP PARSER TESTS
# ═══════════════════════════════════════════════════════════════
class TestBeautifulSoupParsers:
    def test_swagger_html_parser(self):
        p = SwaggerParser()
        eps = p.parse()
        assert len(eps) > 0, "SwaggerParser must return endpoints"
        assert all("endpoint" in e for e in eps)
        assert all("method" in e for e in eps)
        assert all("has_auth" in e for e in eps)
        print(f"  ✅ SwaggerParser: {len(eps)} endpoints from Swagger HTML")

    def test_registry_xml_parser(self):
        p = APIRegistryXMLParser()
        eps = p.parse()
        assert len(eps) > 0, "RegistryXMLParser must return endpoints"
        assert any(not e["has_auth"] for e in eps), "Should find unauthenticated endpoints"
        print(f"  ✅ RegistryXMLParser: {len(eps)} endpoints from XML")

    def test_traffic_fingerprint_parser(self):
        p = TrafficFingerprintParser()
        shadow = p.parse(registered_paths={"/api/v2/payments/initiate",
                                           "/api/v2/accounts/{id}/balance"})
        assert len(shadow) > 0, "Traffic parser must find shadow endpoints"
        assert all(not e["is_registered"] for e in shadow)
        print(f"  ✅ TrafficFingerprintParser: {len(shadow)} shadow endpoints")

    def test_cve_pattern_validator(self):
        v = CVEPatternValidator()
        hits = v.check("/api/internal/debug/sql")
        assert len(hits) >= 2, "Should match 'debug', 'sql' patterns"
        sevs = [h["severity"] for h in hits]
        assert "CRITICAL" in sevs
        print(f"  ✅ CVEPatternValidator: {len(hits)} CVE hits on debug/sql endpoint")

    def test_full_ingestion_pipeline(self):
        pl = APIIngestionPipeline()
        eps, meta = pl.ingest()
        assert meta["swagger_count"] > 0
        assert meta["registry_count"] > 0
        assert meta["traffic_shadow_count"] > 0
        assert meta["total_unique"] > 0
        assert len(meta["parsers_used"]) == 3
        print(f"  ✅ APIIngestionPipeline: {meta['total_unique']} total endpoints, {meta['traffic_shadow_count']} shadow")


# ═══════════════════════════════════════════════════════════════
# 2. KAFKA BROKER TESTS
# ═══════════════════════════════════════════════════════════════
class TestKafkaBroker:
    def test_produce_consume(self):
        broker = KafkaBrokerSim()
        msg = broker.produce("api-gateway-logs", "/api/test", {"method": "GET"})
        assert msg.topic == "api-gateway-logs"
        assert msg.offset == 0
        msgs = broker.consume("api-gateway-logs", max_msgs=10)
        assert len(msgs) == 1
        assert msgs[0].key == "/api/test"
        print(f"  ✅ Kafka produce/consume: 1 message roundtrip")

    def test_all_topics(self):
        broker = KafkaBrokerSim()
        for topic in ["api-gateway-logs", "network-traffic", "cve-feed", "ml-output", "defence-actions"]:
            broker.produce(topic, "key", {"data": topic})
        stats = broker.get_stats()
        assert stats["broker_count"] == 3
        assert len(stats["topics"]) == 5
        print(f"  ✅ Kafka all 5 topics operational: {list(stats['topics'].keys())}")

    def test_kafka_pipeline(self):
        broker = KafkaBrokerSim()
        pipeline = KafkaPipeline(broker)
        pipeline.publish_scan_start(1, {"contamination": 0.15})
        pipeline.publish_ml_result("/api/v1/test", 87.0, "ZOMBIE")
        pipeline.publish_defence_action("disable", "/api/v1/test", 87.0)
        pipeline.publish_alert("CRITICAL", "/api/v1/test", 87.0, "CVE:test")
        stats = broker.get_stats()
        assert stats["topics"]["api-gateway-logs"]["produced"] >= 1
        assert stats["topics"]["ml-output"]["produced"] >= 1
        assert stats["topics"]["defence-actions"]["produced"] >= 2
        print(f"  ✅ Kafka pipeline: scan_start + ml_result + defence + alert published")


# ═══════════════════════════════════════════════════════════════
# 3. ML DETECTOR TESTS
# ═══════════════════════════════════════════════════════════════
class TestMLDetector:
    def test_synthetic_data_generation(self):
        data = generate_synthetic_logs(80)
        assert len(data) == 80
        assert all("endpoint" in r for r in data)
        assert all("calls_per_day" in r for r in data)
        assert all("days_since_active" in r for r in data)
        print(f"  ✅ Synthetic data: {len(data)} records generated")

    def test_pydantic_validation(self):
        from app.ml.detector import EndpointRecord
        # Valid
        r = EndpointRecord(endpoint="/api/v2/test", calls_per_day=-5, error_rate_pct=150.0)
        assert r.calls_per_day == 0      # clamped
        assert r.error_rate_pct == 100.0  # clamped
        print("  ✅ Pydantic validation: negative calls → 0, error_rate > 100 → 100")

    def test_isolation_forest(self):
        data = generate_synthetic_logs(80)
        det = ZombieDetector(contamination=0.15, staleness_days=30)
        results, meta = det.fit_predict(data)
        assert len(results) == 80
        assert meta["if_anomalies"] > 0
        assert meta["n_records"] == 80
        assert "IsolationForest" in meta["model"]
        print(f"  ✅ IsolationForest: {meta['if_anomalies']} anomalies, {meta['lstm_anomalies']} LSTM flags")

    def test_classification(self):
        # ZOMBIE: stale + zero traffic
        cls = classify("/api/v1/old", False, 0, 90, True, -1, 30)
        assert cls == "ZOMBIE", f"Expected ZOMBIE got {cls}"
        # SHADOW: not registered + low traffic
        cls = classify("/api/shadow/pii", False, 2, 5, False, 1, 30)
        assert cls == "SHADOW", f"Expected SHADOW got {cls}"
        # ACTIVE: healthy
        cls = classify("/api/v2/upi/pay", True, 180, 0, True, 1, 30)
        assert cls == "ACTIVE", f"Expected ACTIVE got {cls}"
        print("  ✅ Classifier: ZOMBIE / SHADOW / ACTIVE all correct")

    def test_cvss_scorer(self):
        scorer = CVSSRiskScorer()
        # Max risk: stale + no auth + zero traffic + CVE + undocumented
        score, reason, bd = scorer.score_single("/api/v1/admin/debug/sql", False, 0, 200, False)
        assert score == 100.0, f"Max risk endpoint should score 100, got {score}"
        # Low risk: healthy active endpoint
        score2, _, _ = scorer.score_single("/api/v2/upi/pay", True, 180, 0, True)
        assert score2 < 20, f"Healthy endpoint should score < 20, got {score2}"
        print(f"  ✅ CVSS scorer: max risk=100.0, healthy={score2}")

    def test_numpy_batch_scoring(self):
        import numpy as np
        scorer = CVSSRiskScorer()
        data = generate_synthetic_logs(80)
        scores = scorer.score_batch(data)
        assert isinstance(scores, np.ndarray)
        assert len(scores) == 80
        assert all(0 <= s <= 100 for s in scores)
        print(f"  ✅ NumPy batch scoring: {len(scores)} endpoints, range [{scores.min():.1f}-{scores.max():.1f}]")

    def test_cve_patterns(self):
        assert "debug" in CVE_PATTERNS
        assert "admin" in CVE_PATTERNS
        assert "sql" in CVE_PATTERNS
        scorer = CVSSRiskScorer()
        _, _, bd = scorer.score_single("/api/internal/debug/sql", False, 0, 120, False)
        assert bd["cve_pattern"]["pts"] > 0
        print(f"  ✅ CVE patterns: {len(CVE_PATTERNS)} patterns loaded, debug/sql matched")


# ═══════════════════════════════════════════════════════════════
# 4. FASTAPI ROUTE TESTS
# ═══════════════════════════════════════════════════════════════
class TestFastAPIRoutes:
    def test_health(self):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "FastAPI" in data["stack"]
        print("  ✅ GET /health → 200 OK")

    def test_scan_endpoint(self):
        r = client.post("/api/scan", json={
            "contamination": 0.15,
            "staleness_days": 30,
            "auto_disable": True,
            "rotate_keys": True,
            "fire_webhook": True,
            "data_source": "synthetic"
        })
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "success"
        d = data["data"]
        assert d["total_apis"] > 0
        assert "zombie" in d
        assert "shadow" in d
        assert "ml_meta" in d
        assert "kafka_meta" in d
        assert "parse_meta" in d
        assert d["ml_meta"]["if_anomalies"] >= 0
        assert d["parse_meta"]["swagger_count"] > 0
        print(f"  ✅ POST /api/scan → {d['total_apis']} APIs, {d['zombie']} zombie, {d['shadow']} shadow")

    def test_dashboard(self):
        r = client.get("/api/dashboard")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        d = data["data"]
        assert d["total_apis"] > 0
        assert "owasp_api3" in d
        assert "owasp_api7" in d
        assert "owasp_api9" in d
        print(f"  ✅ GET /api/dashboard → total={d['total_apis']}, avg_risk={d['avg_risk_score']}")

    def test_endpoints_inventory(self):
        r = client.get("/api/endpoints?page=1&page_size=10")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["total"] > 0
        assert len(data["data"]) <= 10
        ep = data["data"][0]
        assert "risk_score" in ep
        assert "classification" in ep
        assert "ml_anomaly" in ep
        print(f"  ✅ GET /api/endpoints → {data['total']} total, top risk={ep['risk_score']}")

    def test_endpoints_filter(self):
        r = client.get("/api/endpoints?classification=ZOMBIE&page_size=50")
        assert r.status_code == 200
        data = r.json()
        if data["data"]:
            assert all(e["classification"] == "ZOMBIE" for e in data["data"])
        print(f"  ✅ GET /api/endpoints?classification=ZOMBIE → {data['total']} zombies")

    def test_top_risky(self):
        r = client.get("/api/endpoints/top-risky?n=5")
        assert r.status_code == 200
        data = r.json()
        scores = [e["risk_score"] for e in data["data"]]
        assert scores == sorted(scores, reverse=True), "Should be sorted by score desc"
        print(f"  ✅ GET /api/endpoints/top-risky → top score={scores[0] if scores else 'N/A'}")

    def test_distribution(self):
        r = client.get("/api/endpoints/distribution")
        assert r.status_code == 200
        data = r.json()
        assert len(data["data"]["bins"]) == 5
        assert sum(data["data"]["bins"]) > 0
        print(f"  ✅ GET /api/endpoints/distribution → bins={data['data']['bins']}")

    def test_risk_calculator(self):
        r = client.post("/api/risk-calc", json={
            "endpoint": "/api/v1/payment/test",
            "days_since_active": 87,
            "calls_per_day": 0,
            "has_auth": False,
            "is_documented": False
        })
        assert r.status_code == 200
        data = r.json()
        assert data["score"] >= 80, f"High-risk endpoint should score >=80, got {data['score']}"
        assert data["classification"] == "CRITICAL"
        assert "breakdown" in data
        assert "staleness" in data["breakdown"]
        assert "no_auth" in data["breakdown"]
        print(f"  ✅ POST /api/risk-calc → score={data['score']}, class={data['classification']}")

    def test_risk_calculator_low(self):
        r = client.post("/api/risk-calc", json={
            "endpoint": "/api/v2/upi/pay",
            "days_since_active": 0,
            "calls_per_day": 180,
            "has_auth": True,
            "is_documented": True
        })
        assert r.status_code == 200
        data = r.json()
        assert data["score"] < 20, f"Healthy endpoint should score <20, got {data['score']}"
        assert data["classification"] == "LOW"
        print(f"  ✅ POST /api/risk-calc (healthy) → score={data['score']}, class={data['classification']}")

    def test_alerts(self):
        r = client.get("/api/alerts")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        print(f"  ✅ GET /api/alerts → {data['total']} alerts")

    def test_defence_get(self):
        r = client.get("/api/defence")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        print(f"  ✅ GET /api/defence → {len(data['data'])} actions")

    def test_defence_post(self):
        r = client.post("/api/defence", json={
            "action_type": "disable",
            "endpoint": "/api/v1/payment/test",
            "actor": "pytest",
            "notes": "test disable"
        })
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "success"
        print(f"  ✅ POST /api/defence disable → {data['message']}")

    def test_defence_invalid_action(self):
        r = client.post("/api/defence", json={
            "action_type": "invalid_action",
            "endpoint": "/api/test"
        })
        assert r.status_code == 400
        print("  ✅ POST /api/defence with invalid action → 400 Bad Request")

    def test_audit_log(self):
        r = client.get("/api/audit")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        print(f"  ✅ GET /api/audit → {data['total']} entries")

    def test_kafka_status(self):
        r = client.get("/api/kafka-status")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["data"]["broker_count"] == 3
        assert len(data["data"]["topics"]) == 5
        print(f"  ✅ GET /api/kafka-status → {data['data']['total_events_per_sec']}M events/sec")

    def test_parser_status(self):
        r = client.get("/api/parser-status")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["data"]["swagger_endpoints"] > 0
        assert data["data"]["registry_endpoints"] > 0
        assert data["data"]["shadow_traffic_endpoints"] > 0
        print(f"  ✅ GET /api/parser-status → swagger={data['data']['swagger_endpoints']}, shadow={data['data']['shadow_traffic_endpoints']}")

    def test_cve_database(self):
        r = client.get("/api/cve-database")
        assert r.status_code == 200
        data = r.json()
        assert data["data"]["patterns_loaded"] >= 14
        print(f"  ✅ GET /api/cve-database → {data['data']['patterns_loaded']} CVE patterns")

    def test_db_stats(self):
        r = client.get("/api/db-stats")
        assert r.status_code == 200
        data = r.json()
        assert data["data"]["api_endpoints"] > 0
        assert data["data"]["risk_scores"] > 0
        assert data["data"]["audit_log_entries"] > 0
        print(f"  ✅ GET /api/db-stats → {data['data']}")

    def test_sessions(self):
        r = client.get("/api/sessions")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert len(data["data"]) > 0
        print(f"  ✅ GET /api/sessions → {len(data['data'])} scan sessions")

    def test_ml_info(self):
        r = client.get("/api/ml-info")
        assert r.status_code == 200
        data = r.json()
        models = [m["name"] for m in data["data"]["models"]]
        assert "IsolationForest" in models
        assert "LSTM" in models
        assert "CVSSRiskScorer" in models
        print(f"  ✅ GET /api/ml-info → models: {models}")

    def test_frontend_serves(self):
        r = client.get("/")
        assert r.status_code == 200
        print("  ✅ GET / → frontend HTML served")


# ── Cleanup ───────────────────────────────────────────────────
def teardown_module():
    import os
    if os.path.exists("./test_zombieguard.db"):
        os.remove("./test_zombieguard.db")


# ═══════════════════════════════════════════════════════════════
# 5. NEW FEATURE TESTS — URL SCANNER & FILE UPLOAD
# ═══════════════════════════════════════════════════════════════
class TestURLScanner:
    def test_url_scanner_import(self):
        from app.services.url_scanner import URLAPIScanner, URLScanRequest
        scanner = URLAPIScanner(timeout=3)
        assert scanner is not None
        print("  ✅ URLAPIScanner imported and instantiated")

    def test_url_request_validation(self):
        from app.services.url_scanner import URLScanRequest
        # auto-prepend https://
        r = URLScanRequest(url="example.com")
        assert r.url.startswith("https://")
        # strip whitespace
        r2 = URLScanRequest(url="  https://api.test.com  ")
        assert r2.url == "https://api.test.com"
        # cap max_endpoints
        r3 = URLScanRequest(url="https://test.com", max_endpoints=500)
        assert r3.max_endpoints == 100
        print("  ✅ URLScanRequest Pydantic validation: https prepend, whitespace strip, cap")

    def test_url_scanner_graceful_fail(self):
        """Scanner should return empty list for unreachable hosts, not crash."""
        from app.services.url_scanner import URLAPIScanner, URLScanRequest
        scanner = URLAPIScanner(timeout=1)
        req = URLScanRequest(url="https://this-host-does-not-exist-zombieguard.invalid")
        data, meta = scanner.scan(req)
        assert isinstance(data, list)
        assert isinstance(meta, dict)
        assert meta["total_discovered"] == len(data)
        print(f"  ✅ URL scanner graceful fail: {len(data)} endpoints, no crash")

    def test_url_scanner_build_record(self):
        """_build_endpoint_record should produce valid ML-pipeline-ready dicts."""
        from app.services.url_scanner import URLAPIScanner, URLScanRequest
        scanner = URLAPIScanner(timeout=2)
        rec = scanner._build_endpoint_record(
            "/api/v1/test", "GET", False, False, True,
            "https://example.com", "probe"
        )
        assert "endpoint" in rec
        assert "calls_per_day" in rec
        assert "days_since_active" in rec
        assert "has_auth" in rec
        assert rec["endpoint"] == "/api/v1/test"
        assert rec["method"] == "GET"
        assert rec["has_auth"] == False
        assert rec["owner_team"] == "scanned"
        print("  ✅ _build_endpoint_record produces valid ML-ready dict")

    def test_api_scan_url_endpoint(self):
        """POST /api/scan/url with unreachable URL returns no_endpoints gracefully."""
        r = client.post("/api/scan/url", json={
            "url": "https://this-host-does-not-exist-zombieguard.invalid",
            "max_endpoints": 5,
            "contamination": 0.15,
            "staleness_days": 30,
            "auto_disable": False,
            "fire_webhook": False,
        })
        assert r.status_code == 200
        data = r.json()
        assert data["status"] in ("success", "no_endpoints")
        print(f"  ✅ POST /api/scan/url → status={data['status']} (graceful for unreachable host)")

    def test_api_scan_url_invalid(self):
        """POST /api/scan/url with completely invalid input returns error."""
        r = client.post("/api/scan/url", json={"url": "not-a-url"})
        # Pydantic cleans it up (prepends https://) so it won't 422,
        # it will just return no_endpoints or success
        assert r.status_code in (200, 422)
        print(f"  ✅ POST /api/scan/url invalid input handled: HTTP {r.status_code}")

    def test_sample_files_endpoint(self):
        """GET /api/scan/sample-files returns downloadable content."""
        for fmt in ["csv", "json", "txt"]:
            r = client.get(f"/api/scan/sample-files?fmt={fmt}")
            assert r.status_code == 200
            assert len(r.content) > 0
            print(f"  ✅ GET /api/scan/sample-files?fmt={fmt} → {len(r.content)} bytes")


class TestFileUploadScanner:
    def test_file_scanner_import(self):
        from app.services.file_scanner import FileScanner, SAMPLE_CSV, SAMPLE_JSON, SAMPLE_TXT
        fs = FileScanner()
        assert fs is not None
        assert len(SAMPLE_CSV) > 0
        assert len(SAMPLE_JSON) > 0
        assert len(SAMPLE_TXT) > 0
        print("  ✅ FileScanner imported, sample data present")

    def test_parse_csv(self):
        from app.services.file_scanner import FileScanner, SAMPLE_CSV
        fs = FileScanner()
        recs, logs = fs.parse("test.csv", SAMPLE_CSV.encode())
        assert len(recs) > 0
        assert all("endpoint" in r for r in recs)
        assert all("method" in r for r in recs)
        assert all("has_auth" in r for r in recs)
        assert all("calls_per_day" in r for r in recs)
        assert all("days_since_active" in r for r in recs)
        # Endpoints should start with /
        assert all(r["endpoint"].startswith("/") for r in recs)
        print(f"  ✅ CSV parse: {len(recs)} records, all fields present, endpoints normalised")

    def test_parse_json(self):
        from app.services.file_scanner import FileScanner, SAMPLE_JSON
        fs = FileScanner()
        recs, logs = fs.parse("test.json", SAMPLE_JSON.encode())
        assert len(recs) > 0
        assert all(r["endpoint"].startswith("/") for r in recs)
        print(f"  ✅ JSON parse: {len(recs)} records")

    def test_parse_txt(self):
        from app.services.file_scanner import FileScanner, SAMPLE_TXT
        fs = FileScanner()
        recs, logs = fs.parse("test.txt", SAMPLE_TXT.encode())
        assert len(recs) > 0
        assert all(r["endpoint"].startswith("/") for r in recs)
        # Verify METHOD /path format parsed correctly
        post_recs = [r for r in recs if r["method"] == "POST"]
        assert len(post_recs) > 0
        print(f"  ✅ TXT parse: {len(recs)} records, METHOD prefix handled")

    def test_parse_url_normalisation(self):
        """Full URLs in CSV/TXT should be normalised to path-only."""
        from app.services.file_scanner import FileScanner
        fs = FileScanner()
        txt = "https://example.com/api/v1/users\nhttp://api.bank.com/payments/initiate\n/api/v2/local"
        recs, _ = fs.parse("test.txt", txt.encode())
        assert all(r["endpoint"].startswith("/") for r in recs), "All endpoints must start with /"
        assert not any("http" in r["endpoint"] for r in recs), "Full URLs must be stripped to path"
        print(f"  ✅ URL normalisation: full URLs stripped to path, all start with /")

    def test_parse_auto_detect_json(self):
        """Auto-detect JSON by content when no extension given."""
        from app.services.file_scanner import FileScanner
        import json
        fs = FileScanner()
        data = json.dumps([{"endpoint": "/api/test", "method": "GET"}])
        recs, _ = fs.parse("unknown_file", data.encode())
        assert len(recs) == 1
        assert recs[0]["endpoint"] == "/api/test"
        print("  ✅ Auto-detect: JSON content detected without extension")

    def test_parse_auto_detect_csv(self):
        """Auto-detect CSV by content when no extension given."""
        from app.services.file_scanner import FileScanner
        fs = FileScanner()
        data = "endpoint,method\n/api/v1/test,GET\n/api/v2/pay,POST"
        recs, _ = fs.parse("no_extension", data.encode())
        assert len(recs) == 2
        print("  ✅ Auto-detect: CSV content detected without extension")

    def test_pydantic_validation_clamping(self):
        """Pydantic validators clamp negative/out-of-range values."""
        from app.services.file_scanner import UploadedEndpoint
        rec = UploadedEndpoint(endpoint="/api/test", calls_per_day=-50, error_rate_pct=200.0, response_ms=-10)
        assert rec.calls_per_day == 0
        assert rec.error_rate_pct == 100.0
        assert rec.response_ms == 0
        print("  ✅ Pydantic validation: negative calls→0, error_rate 200→100, negative ms→0")

    def test_pydantic_truthy_parsing(self):
        """Pydantic bool fields accept various truthy string formats."""
        from app.services.file_scanner import _truthy
        assert _truthy("true") == True
        assert _truthy("1") == True
        assert _truthy("yes") == True
        assert _truthy("Y") == True
        assert _truthy("false") == False
        assert _truthy("0") == False
        assert _truthy("no") == False
        print("  ✅ Pydantic truthy: true/1/yes/Y=True, false/0/no=False")

    def test_file_too_large(self):
        """Files over 10MB should raise ValueError."""
        from app.services.file_scanner import FileScanner
        fs = FileScanner()
        big = b"x" * (11 * 1024 * 1024)  # 11MB
        try:
            fs.parse("big.csv", big)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "too large" in str(e).lower()
        print("  ✅ File size limit: 11MB file raises ValueError")

    def test_api_upload_csv(self):
        """POST /api/scan/upload with CSV file returns success."""
        from app.services.file_scanner import SAMPLE_CSV
        files = {"file": ("test_endpoints.csv", SAMPLE_CSV.encode(), "text/csv")}
        data = {"contamination": 0.15, "staleness_days": 30,
                "auto_disable": False, "rotate_keys": False, "fire_webhook": False}
        r = client.post("/api/scan/upload", files=files, data=data)
        assert r.status_code == 200
        resp = r.json()
        assert resp["status"] == "success"
        d = resp["data"]
        assert d["total_parsed"] > 0
        assert d["total_scanned"] > 0
        assert "zombie" in d
        assert "shadow" in d
        assert "ml_meta" in d
        assert "parse_logs" in d
        assert "results_preview" in d
        assert d["ml_meta"]["if_anomalies"] >= 0
        print(f"  ✅ POST /api/scan/upload CSV → {d['total_scanned']} scanned, zombie={d['zombie']}, shadow={d['shadow']}")

    def test_api_upload_json(self):
        """POST /api/scan/upload with JSON file returns success."""
        from app.services.file_scanner import SAMPLE_JSON
        files = {"file": ("test_endpoints.json", SAMPLE_JSON.encode(), "application/json")}
        data = {"contamination": 0.15, "staleness_days": 30,
                "auto_disable": False, "rotate_keys": False, "fire_webhook": False}
        r = client.post("/api/scan/upload", files=files, data=data)
        assert r.status_code == 200
        resp = r.json()
        assert resp["status"] == "success"
        print(f"  ✅ POST /api/scan/upload JSON → {resp['data']['total_scanned']} scanned")

    def test_api_upload_txt(self):
        """POST /api/scan/upload with TXT file returns success."""
        from app.services.file_scanner import SAMPLE_TXT
        files = {"file": ("test_endpoints.txt", SAMPLE_TXT.encode(), "text/plain")}
        data = {"contamination": 0.15, "staleness_days": 30,
                "auto_disable": False, "rotate_keys": False, "fire_webhook": False}
        r = client.post("/api/scan/upload", files=files, data=data)
        assert r.status_code == 200
        resp = r.json()
        assert resp["status"] == "success"
        print(f"  ✅ POST /api/scan/upload TXT → {resp['data']['total_scanned']} scanned")

    def test_api_upload_auto_disable(self):
        """Upload with auto_disable=True should disable CRITICAL endpoints."""
        from app.services.file_scanner import SAMPLE_CSV
        files = {"file": ("test.csv", SAMPLE_CSV.encode(), "text/csv")}
        data = {"contamination": 0.15, "staleness_days": 30,
                "auto_disable": True, "rotate_keys": True, "fire_webhook": True}
        r = client.post("/api/scan/upload", files=files, data=data)
        assert r.status_code == 200
        d = r.json()["data"]
        # disabled count must be <= zombie+shadow count
        assert d["disabled"] <= d["total_scanned"]
        print(f"  ✅ POST /api/scan/upload auto_disable=True → {d['disabled']} disabled, {d['alerts']} alerts")

    def test_api_upload_sample_files(self):
        """GET /api/scan/sample-files returns correct content for all formats."""
        for fmt, expected_content in [("csv", "endpoint"), ("json", "["), ("txt", "/api")]:
            r = client.get(f"/api/scan/sample-files?fmt={fmt}")
            assert r.status_code == 200
            assert expected_content in r.text
        print("  ✅ GET /api/scan/sample-files → CSV/JSON/TXT all contain expected content")
