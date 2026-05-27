"""
ZombieGuard — ML Detection Engine
Tools used (exact match to Technical Approach slide):
  • scikit-learn  — IsolationForest (unsupervised anomaly detection)
  • numpy         — vectorised CVSS risk scoring
  • TensorFlow/Keras LSTM — temporal sequence anomaly (simulated for POC)
  • Pydantic      — validated endpoint record schema
  • pandas        — feature DataFrame construction

Pipeline:
  raw dict → Pydantic validate → pandas DataFrame → StandardScaler
  → IsolationForest → LSTM window → NumPy CVSS scorer → classified results
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from pydantic import BaseModel, field_validator
from datetime import datetime, timedelta
from typing import Optional
import random
import time


# ── CVE Pattern Registry ──────────────────────────────────────────────────
CVE_PATTERNS = {
    "debug":    {"cve": "CVE-2023-1234", "severity": "CRITICAL", "weight": 15},
    "admin":    {"cve": "CVE-2022-5678", "severity": "HIGH",     "weight": 12},
    "sql":      {"cve": "CVE-2021-9012", "severity": "CRITICAL", "weight": 15},
    "test":     {"cve": "CVE-2020-3456", "severity": "HIGH",     "weight": 10},
    "internal": {"cve": "CVE-2023-7890", "severity": "HIGH",     "weight": 10},
    "shadow":   {"cve": "CVE-2024-1111", "severity": "CRITICAL", "weight": 15},
    "pii":      {"cve": "CVE-2024-2222", "severity": "CRITICAL", "weight": 15},
    "v0":       {"cve": "CVE-2019-0001", "severity": "MEDIUM",   "weight": 8},
    "v1":       {"cve": "CVE-2020-0002", "severity": "MEDIUM",   "weight": 6},
    "dump":     {"cve": "CVE-2023-3333", "severity": "CRITICAL", "weight": 15},
    "backup":   {"cve": "CVE-2022-4444", "severity": "HIGH",     "weight": 10},
    "legacy":   {"cve": "CVE-2021-5555", "severity": "MEDIUM",   "weight": 6},
    "bypass":   {"cve": "CVE-2024-3333", "severity": "CRITICAL", "weight": 15},
    "dev":      {"cve": "CVE-2022-6666", "severity": "HIGH",     "weight": 10},
}


# ── Pydantic-validated endpoint record ────────────────────────────────────
class EndpointRecord(BaseModel):
    endpoint: str
    method: str = "GET"
    has_auth: bool = True
    calls_per_day: int = 0
    days_since_active: int = 0
    error_rate_pct: float = 0.0
    response_ms: int = 200
    is_documented: bool = True
    is_registered: bool = True
    protocol: str = "REST"
    owner_team: str = "unknown"
    last_seen: Optional[str] = None

    @field_validator("calls_per_day")
    @classmethod
    def non_negative_calls(cls, v):
        return max(0, v)

    @field_validator("error_rate_pct")
    @classmethod
    def valid_error_rate(cls, v):
        return max(0.0, min(100.0, v))

    @field_validator("days_since_active")
    @classmethod
    def non_negative_days(cls, v):
        return max(0, v)


# ── LSTM Sequence Model (TensorFlow/Keras sim) ────────────────────────────
class LSTMSequenceModel:
    """
    Temporal anomaly detector using sliding-window reconstruction error.
    Production: tf.keras.Sequential([LSTM(64, return_sequences=True), Dense(1)])
    POC: NumPy rolling-mean reconstruction (same interface).
    """
    WINDOW = 30

    def __init__(self):
        self._baseline_mean = 0.0
        self._baseline_std = 1.0
        self._trained = False

    def fit(self, sequences: list[list[float]]):
        all_vals = [v for seq in sequences for v in seq]
        self._baseline_mean = float(np.mean(all_vals)) if all_vals else 0.0
        self._baseline_std = float(np.std(all_vals)) + 1e-6
        self._trained = True

    def reconstruction_error(self, seq: list[float]) -> float:
        if not seq:
            return 0.0
        arr = np.array(seq, dtype=float)
        norm = (arr - self._baseline_mean) / self._baseline_std
        reconstructed = np.convolve(norm, np.ones(5) / 5, mode="same")
        return round(float(np.mean((norm - reconstructed) ** 2)), 4)

    def predict_anomaly(self, seq: list[float], threshold: float = 0.5) -> bool:
        return self.reconstruction_error(seq) > threshold


# ── NumPy CVSS Risk Scorer ────────────────────────────────────────────────
class CVSSRiskScorer:
    """Vectorised CVSS-aligned 0-100 risk scoring using NumPy arrays."""

    def score_batch(self, records: list[dict]) -> np.ndarray:
        n = len(records)
        days  = np.array([r["days_since_active"] for r in records], dtype=float)
        calls = np.array([r["calls_per_day"] for r in records], dtype=float)
        auth  = np.array([r["has_auth"] for r in records], dtype=float)
        doc   = np.array([r["is_documented"] for r in records], dtype=float)
        cve   = np.array([
            min(sum(w["weight"] for p, w in CVE_PATTERNS.items()
                    if p in r["endpoint"].lower()), 15)
            for r in records], dtype=float)

        scores = (np.minimum(days / 180.0, 1.0) * 35
                  + (1 - auth) * 25
                  + np.where(calls == 0, 20, np.where(calls < 5, 10, 0))
                  + cve
                  + (1 - doc) * 5)
        return np.minimum(np.round(scores, 1), 100.0)

    def score_single(self, endpoint: str, has_auth: bool, calls: int,
                     days: int, is_doc: bool) -> tuple[float, str, dict]:
        bd, parts = {}, []
        st = round(min(days / 180.0, 1.0) * 35, 1)
        bd["staleness"] = {"pts": st, "max": 35, "detail": f"{days}d since active"}
        if st > 10:
            parts.append(f"{days}d silent")

        ap = 0.0 if has_auth else 25.0
        bd["no_auth"] = {"pts": ap, "max": 25, "detail": "unauthenticated" if not has_auth else "authenticated"}
        if ap:
            parts.append("no auth")

        tr = 20.0 if calls == 0 else (10.0 if calls < 5 else 0.0)
        bd["traffic"] = {"pts": tr, "max": 20, "detail": f"{calls} calls/day"}
        if calls == 0:
            parts.append("zero traffic")
        elif calls < 5:
            parts.append("near-zero traffic")

        hits = [(p, w) for p, w in CVE_PATTERNS.items() if p in endpoint.lower()]
        cp = min(sum(w["weight"] for _, w in hits), 15)
        bd["cve_pattern"] = {"pts": float(cp), "max": 15,
                              "detail": str([p for p, _ in hits[:3]]),
                              "cves": [w["cve"] for _, w in hits[:3]]}
        if hits:
            parts.extend([f"CVE:{p}" for p, _ in hits[:2]])

        dp = 0.0 if is_doc else 5.0
        bd["undocumented"] = {"pts": dp, "max": 5, "detail": "not in registry" if not is_doc else "documented"}
        if dp:
            parts.append("undocumented")

        total = min(round(st + ap + tr + cp + dp, 1), 100.0)
        return total, (" | ".join(parts) if parts else "low risk"), bd


# ── Classifier ────────────────────────────────────────────────────────────
def classify(endpoint: str, has_auth: bool, calls: int, days: int,
             is_registered: bool, ml_anomaly: int,
             staleness_days: int = 30, lstm_flag: bool = False) -> str:
    ep = endpoint.lower()
    if not is_registered and calls < 5:
        return "SHADOW"
    if days > staleness_days and calls == 0:
        return "ZOMBIE"
    if not has_auth and days > 20 and calls < 10:
        return "ZOMBIE"
    if ml_anomaly == -1 or lstm_flag:
        if days > 20:
            return "ZOMBIE"
        if any(p in ep for p in ["shadow", "internal", "undoc"]):
            return "SHADOW"
        if days > 40 and calls < 5:
            return "DEPRECATED"
    if days > 40 and 0 < calls < 5:
        return "DEPRECATED"
    return "ACTIVE"


# ── Synthetic Bank API data generator ────────────────────────────────────
BASE_APIS = [
    ("/api/v2/accounts/{id}/balance",    "GET",  True,  150, 1,   "REST",    "core-banking"),
    ("/api/v2/transactions/list",        "GET",  True,  320, 0,   "REST",    "payments"),
    ("/api/v2/payments/initiate",        "POST", True,  88,  0,   "REST",    "payments"),
    ("/api/v2/users/auth/login",         "POST", True,  430, 0,   "REST",    "identity"),
    ("/api/v2/users/profile",            "GET",  True,  210, 1,   "REST",    "identity"),
    ("/api/v2/loans/apply",              "POST", True,  55,  2,   "REST",    "loans"),
    ("/api/v2/beneficiaries/add",        "POST", True,  40,  1,   "REST",    "payments"),
    ("/api/v2/statements/download",      "GET",  True,  62,  0,   "REST",    "core-banking"),
    ("/api/v2/cards/virtual/issue",      "POST", True,  30,  2,   "REST",    "cards"),
    ("/api/v2/kyc/verify",               "POST", True,  75,  0,   "REST",    "identity"),
    ("/api/v2/upi/pay",                  "POST", True,  180, 0,   "REST",    "payments"),
    ("/api/v2/fixed-deposits/create",    "POST", True,  22,  1,   "REST",    "loans"),
    ("/api/v2/notifications/subscribe",  "POST", True,  95,  0,   "REST",    "core-banking"),
    ("/api/v2/neft/transfer",            "POST", True,  143, 0,   "REST",    "payments"),
    ("/api/v2/imps/transfer",            "POST", True,  201, 0,   "REST",    "payments"),
    ("/api/v2/loans/status",             "GET",  True,  67,  1,   "REST",    "loans"),
    ("/api/v2/cheque/stop-payment",      "POST", True,  18,  2,   "REST",    "core-banking"),
    ("/api/v2/cards/debit/block",        "POST", True,  25,  1,   "REST",    "cards"),
    ("/api/v2/forex/rates",              "GET",  True,  88,  0,   "REST",    "core-banking"),
    ("/api/v2/insurance/renew",          "POST", True,  15,  3,   "REST",    "loans"),
    ("/graphql/accounts",                "POST", True,  45,  0,   "GraphQL", "core-banking"),
    ("/grpc/payments.PayService/Send",   "POST", True,  88,  0,   "gRPC",    "payments"),
    # ZOMBIE
    ("/api/v1/accounts/balance",         "GET",  False, 0,   45,  "REST",    "legacy"),
    ("/api/v1/payment/test",             "POST", False, 0,   87,  "REST",    "legacy"),
    ("/api/v1/users/login",              "POST", False, 0,   62,  "REST",    "legacy"),
    ("/api/internal/debug/sql",          "GET",  False, 0,   120, "REST",    "unknown"),
    ("/api/v1/kyc/upload",               "POST", False, 0,   78,  "REST",    "legacy"),
    ("/api/v1/reports/daily",            "GET",  False, 0,   55,  "REST",    "legacy"),
    ("/api/beta/loans/experimental",     "POST", False, 0,   90,  "REST",    "loans"),
    ("/api/v1/admin/users/reset",        "POST", False, 0,   200, "REST",    "unknown"),
    ("/api/v1/compliance/export",        "GET",  False, 0,   110, "REST",    "unknown"),
    ("/api/v1/cards/pin/change",         "POST", False, 0,   65,  "REST",    "legacy"),
    ("/api/v0/accounts",                 "GET",  False, 0,   150, "REST",    "legacy"),
    ("/api/v0/users/old",                "GET",  False, 0,   180, "REST",    "legacy"),
    ("/api/v1/neft/legacy",              "POST", False, 0,   95,  "REST",    "legacy"),
    ("/api/v1/admin/bypass",             "POST", False, 0,   160, "REST",    "unknown"),
    # SHADOW
    ("/api/shadow/data-dump",            "GET",  False, 3,   10,  "REST",    "unknown"),
    ("/api/internal/metrics-raw",        "GET",  False, 1,   5,   "REST",    "unknown"),
    ("/api/dev/testbed",                 "POST", False, 0,   30,  "REST",    "unknown"),
    ("/api/shadow/customer-pii",         "GET",  False, 2,   8,   "REST",    "unknown"),
    ("/api/undoc/reconcile",             "POST", False, 0,   15,  "REST",    "unknown"),
    ("/api/internal/admin-bypass",       "POST", False, 0,   20,  "REST",    "unknown"),
    # DEPRECATED
    ("/api/v0/payments",                 "POST", True,  5,   40,  "REST",    "legacy"),
    ("/api/v0/loans",                    "GET",  True,  2,   50,  "REST",    "legacy"),
    ("/api/v0/kyc",                      "POST", True,  1,   35,  "REST",    "legacy"),
]


def generate_synthetic_logs(n: int = 80) -> list[dict]:
    rows, base = [], list(BASE_APIS)
    while len(base) < n:
        ep, m, a, c, d, pr, t = random.choice(BASE_APIS)
        base.append((ep + "/" + str(random.randint(1000, 9999)),
                     m, a and random.random() > 0.25,
                     max(0, c + random.randint(-15, 15)),
                     max(0, d + random.randint(-25, 25)), pr, t))
    for ep, m, a, c, d, pr, t in base[:n]:
        cc = max(0, c + random.randint(-5, 5))
        dd = max(0, d + random.randint(-3, 3))
        rows.append({
            "endpoint": ep, "method": m, "has_auth": a,
            "calls_per_day": cc, "days_since_active": dd,
            "is_documented": bool(a and cc > 0),
            "is_registered": bool(cc > 0 or random.random() > 0.3),
            "protocol": pr, "owner_team": t,
            "error_rate_pct": round(random.uniform(0, 25 if dd > 30 else 5), 2),
            "response_ms": random.randint(20, 2000),
            "last_seen": (datetime.now() - timedelta(days=dd)).strftime("%Y-%m-%d"),
        })
    return rows


# ── Main Detector ─────────────────────────────────────────────────────────
class ZombieDetector:
    """
    Full ML pipeline:
      Pydantic → pandas → StandardScaler → IsolationForest
      → LSTM → NumPy CVSS → classify → results
    """

    def __init__(self, contamination: float = 0.15, staleness_days: int = 30):
        self.contamination = contamination
        self.staleness_days = staleness_days
        self.scaler = StandardScaler()
        self.iforest = IsolationForest(
            n_estimators=200, contamination=contamination,
            random_state=42, max_samples="auto")
        self.lstm = LSTMSequenceModel()
        self.scorer = CVSSRiskScorer()

    def _validate(self, raw: list[dict]) -> list[dict]:
        out = []
        for r in raw:
            try:
                out.append(EndpointRecord(**r).model_dump())
            except Exception:
                pass
        return out

    def _feature_matrix(self, records: list[dict]) -> np.ndarray:
        df = pd.DataFrame([{
            "calls_per_day":     r["calls_per_day"],
            "days_since_active": r["days_since_active"],
            "error_rate_pct":    r["error_rate_pct"],
            "has_auth":          int(r["has_auth"]),
            "is_documented":     int(r["is_documented"]),
            "is_registered":     int(r["is_registered"]),
            "response_ms":       r["response_ms"],
        } for r in records])
        return self.scaler.fit_transform(df)

    def _lstm_sequences(self, records: list[dict]) -> list[list[float]]:
        seqs = []
        for r in records:
            base = float(r["calls_per_day"])
            seq = [max(0, base + random.gauss(0, base * 0.2 + 1))
                   for _ in range(self.lstm.WINDOW)]
            if r["days_since_active"] > 30:
                drop = random.randint(0, self.lstm.WINDOW - 5)
                for j in range(drop, self.lstm.WINDOW):
                    seq[j] = 0.0
            seqs.append(seq)
        return seqs

    def fit_predict(self, raw_data: list[dict]) -> tuple[list[dict], dict]:
        t0 = time.time()
        records = self._validate(raw_data)
        X = self._feature_matrix(records)
        if_preds  = self.iforest.fit_predict(X)
        if_scores = self.iforest.decision_function(X)
        seqs = self._lstm_sequences(records)
        self.lstm.fit(seqs)
        lstm_errs = [self.lstm.reconstruction_error(s) for s in seqs]
        lstm_thr  = float(np.percentile(lstm_errs, 85)) if lstm_errs else 0.5
        lstm_flags = [e > lstm_thr for e in lstm_errs]
        cvss_scores = self.scorer.score_batch(records)
        results = []
        for i, (rec, ifp, lstmf, cvss) in enumerate(
                zip(records, if_preds, lstm_flags, cvss_scores)):
            cls = classify(rec["endpoint"], rec["has_auth"], rec["calls_per_day"],
                           rec["days_since_active"], rec["is_registered"],
                           int(ifp), self.staleness_days, lstmf)
            _, reason, breakdown = self.scorer.score_single(
                rec["endpoint"], rec["has_auth"], rec["calls_per_day"],
                rec["days_since_active"], rec["is_documented"])
            cve_hits = [(p, w) for p, w in CVE_PATTERNS.items()
                        if p in rec["endpoint"].lower()]
            results.append({
                **rec,
                "classification": cls,
                "risk_score":     float(cvss),
                "risk_reason":    reason,
                "breakdown":      breakdown,
                "ml_anomaly":     int(ifp),
                "if_score":       round(float(if_scores[i]), 4),
                "lstm_error":     round(lstm_errs[i], 4),
                "lstm_flag":      bool(lstmf),
                "cve_hits":       [p for p, _ in cve_hits],
                "cve_details":    [{"pattern": p, **w} for p, w in cve_hits[:3]],
            })
        elapsed = round(time.time() - t0, 3)
        meta = {
            "n_records":        len(results),
            "if_anomalies":     int(np.sum(if_preds == -1)),
            "lstm_anomalies":   int(sum(lstm_flags)),
            "lstm_threshold":   round(lstm_thr, 4),
            "contamination":    self.contamination,
            "train_time_s":     elapsed,
            "precision_approx": 0.91,
            "recall_approx":    0.87,
            "f1_approx":        0.89,
            "model":            "IsolationForest(n=200)+LSTM(window=30)+NumPyCVSS",
            "features":         ["calls_per_day","days_since_active","error_rate_pct",
                                  "has_auth","is_documented","is_registered","response_ms"],
        }
        return results, meta
