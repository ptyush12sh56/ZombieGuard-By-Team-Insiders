"""
ZombieGuard — SQL Alchemy Database Models
Tables: api_endpoints, risk_scores, audit_log, cve_matches, defence_actions, alerts
"""
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
)
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()


class APIEndpoint(Base):
    __tablename__ = "api_endpoints"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    endpoint        = Column(String(512), nullable=False, unique=True)
    method          = Column(String(10), default="GET")
    has_auth        = Column(Boolean, default=True)
    calls_per_day   = Column(Integer, default=0)
    days_since_active = Column(Integer, default=0)
    last_seen       = Column(String(30), nullable=True)
    protocol        = Column(String(20), default="REST")
    owner_team      = Column(String(80), default="unknown")
    is_documented   = Column(Boolean, default=True)
    is_registered   = Column(Boolean, default=True)
    error_rate_pct  = Column(Float, default=0.0)
    response_ms     = Column(Integer, default=200)
    created_at      = Column(DateTime, default=datetime.utcnow)

    risk_scores     = relationship("RiskScore", back_populates="endpoint_rel", cascade="all, delete")
    cve_matches     = relationship("CVEMatch", back_populates="endpoint_rel", cascade="all, delete")


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    endpoint_id     = Column(Integer, ForeignKey("api_endpoints.id"), nullable=False)
    score           = Column(Float, default=0.0)
    classification  = Column(String(20), default="ACTIVE")   # ACTIVE/ZOMBIE/SHADOW/DEPRECATED
    risk_reason     = Column(Text, default="")
    ml_anomaly      = Column(Integer, default=1)             # -1 = anomaly, 1 = normal
    scanned_at      = Column(DateTime, default=datetime.utcnow)

    endpoint_rel    = relationship("APIEndpoint", back_populates="risk_scores")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    action          = Column(String(50), nullable=False)     # DISABLE / ENABLE / ROTATE_KEY / WHITELIST / ALERT
    endpoint        = Column(String(512), nullable=False)
    actor           = Column(String(80), default="ZombieGuard-AutoBot")
    result          = Column(String(20), default="SUCCESS")
    notes           = Column(Text, default="")
    timestamp       = Column(DateTime, default=datetime.utcnow)


class CVEMatch(Base):
    __tablename__ = "cve_matches"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    endpoint_id     = Column(Integer, ForeignKey("api_endpoints.id"), nullable=False)
    cve_pattern     = Column(String(50))
    severity        = Column(String(10), default="HIGH")
    matched_at      = Column(DateTime, default=datetime.utcnow)

    endpoint_rel    = relationship("APIEndpoint", back_populates="cve_matches")


class DefenceAction(Base):
    __tablename__ = "defence_actions"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    action_type     = Column(String(30), nullable=False)     # disable / rotate / alert / whitelist
    endpoint        = Column(String(512), nullable=False)
    risk_score      = Column(Float, default=0.0)
    is_auto         = Column(Boolean, default=False)
    triggered_by    = Column(String(80), default="system")
    timestamp       = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    severity        = Column(String(20), nullable=False)     # CRITICAL / HIGH / MEDIUM
    endpoint        = Column(String(512), nullable=False)
    risk_score      = Column(Float, default=0.0)
    reason          = Column(Text, default="")
    channel         = Column(String(30), default="webhook")  # slack / email / pagerduty
    dispatched      = Column(Boolean, default=False)
    timestamp       = Column(DateTime, default=datetime.utcnow)


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    total_apis      = Column(Integer, default=0)
    zombie_count    = Column(Integer, default=0)
    shadow_count    = Column(Integer, default=0)
    deprecated_count= Column(Integer, default=0)
    active_count    = Column(Integer, default=0)
    disabled_count  = Column(Integer, default=0)
    alert_count     = Column(Integer, default=0)
    contamination   = Column(Float, default=0.15)
    staleness_days  = Column(Integer, default=30)
    scan_duration_s = Column(Float, default=0.0)
    started_at      = Column(DateTime, default=datetime.utcnow)
    completed_at    = Column(DateTime, nullable=True)
