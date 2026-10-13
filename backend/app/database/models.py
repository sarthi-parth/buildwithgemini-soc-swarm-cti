import datetime
import uuid
from typing import Optional, List
from sqlalchemy import (
    Column, String, Text, Integer, Float, Boolean, DateTime, ForeignKey, Index, Enum
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

def generate_uuid() -> str:
    return str(uuid.uuid4())

def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class Source(Base):
    __tablename__ = "sources"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    source_type = Column(String(50), nullable=False) # rss, api, advisory, manual
    url = Column(String(500), nullable=False, unique=True)
    enabled = Column(Boolean, default=True)
    polling_interval = Column(Integer, default=15) # minutes
    last_polled_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    documents = relationship("SourceDocument", back_populates="source", cascade="all, delete-orphan")


class SourceDocument(Base):
    __tablename__ = "source_documents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    source_id = Column(String(36), ForeignKey("sources.id"), nullable=True)
    title = Column(String(500), nullable=False)
    canonical_url = Column(String(1000), nullable=False, unique=True)
    content_hash = Column(String(64), nullable=False, index=True)
    raw_content = Column(Text, nullable=True)
    extracted_text = Column(Text, nullable=True)
    published_at = Column(DateTime, nullable=True)
    discovered_at = Column(DateTime, default=utc_now)
    processing_status = Column(String(50), default="DISCOVERED") # DISCOVERED, PROCESSING, COMPLETED, FAILED

    source = relationship("Source", back_populates="documents")
    incidents = relationship("Incident", back_populates="primary_source_doc")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    primary_source_doc_id = Column(String(36), ForeignKey("source_documents.id"), nullable=True)
    title = Column(String(500), nullable=False)
    summary = Column(Text, nullable=True)
    affected_organization = Column(String(200), nullable=True)
    affected_systems = Column(Text, nullable=True)
    initial_access_vector = Column(Text, nullable=True)
    root_cause_analysis = Column(Text, nullable=True)
    severity = Column(String(20), default="MEDIUM") # LOW, MEDIUM, HIGH, CRITICAL
    confidence_score = Column(Float, default=0.8) # 0.0 to 1.0
    status = Column(String(50), default="DISCOVERED") # DISCOVERED, INVESTIGATING, VERIFYING, READY_TO_PUBLISH, PUBLISHED, NEEDS_REVIEW, FAILED
    is_demo = Column(Boolean, default=False)
    incident_date = Column(DateTime, nullable=True)
    disclosure_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    primary_source_doc = relationship("SourceDocument", back_populates="incidents")
    iocs = relationship("IncidentIOC", back_populates="incident", cascade="all, delete-orphan")
    techniques = relationship("IncidentTechnique", back_populates="incident", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="incident", cascade="all, delete-orphan")
    recommendations = relationship("MitigationRecommendation", back_populates="incident", cascade="all, delete-orphan")
    correlations = relationship("HistoricalCorrelation", back_populates="incident", cascade="all, delete-orphan")
    agent_runs = relationship("AgentRun", back_populates="incident", cascade="all, delete-orphan")
    verification_reviews = relationship("VerificationReview", back_populates="incident", cascade="all, delete-orphan")
    notifications = relationship("Notification", back_populates="incident")
    ioas = relationship("IOA", back_populates="incident", cascade="all, delete-orphan")


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    ioc_type = Column(String(50), nullable=False, index=True) # ipv4, ipv6, domain, url, sha256, sha1, md5, cve, email, malware_family
    normalized_value = Column(String(500), nullable=False, unique=True, index=True)
    defanged_value = Column(String(500), nullable=False)
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)
    times_observed = Column(Integer, default=1)
    enrichment_status = Column(String(50), default="UNENRICHED") # UNENRICHED, ENRICHED, FAILED
    enrichment_data = Column(Text, nullable=True) # JSON
    threat_status = Column(String(50), default="SUSPICIOUS") # SUSPICIOUS, CONFIRMED_MALICIOUS, BENIGN, UNKNOWN

    incident_associations = relationship("IncidentIOC", back_populates="ioc", cascade="all, delete-orphan")


class IncidentIOC(Base):
    __tablename__ = "incident_iocs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    ioc_id = Column(String(36), ForeignKey("iocs.id"), nullable=False)
    context_role = Column(String(200), nullable=True) # e.g., C2 Server, Exfiltration Endpoint, Dropped Payload
    supporting_passage = Column(Text, nullable=True)
    confidence = Column(Float, default=1.0)
    created_at = Column(DateTime, default=utc_now)

    incident = relationship("Incident", back_populates="iocs")
    ioc = relationship("IOC", back_populates="incident_associations")


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id = Column(String(50), primary_key=True) # e.g. T1190
    tactic = Column(String(100), nullable=False) # Initial Access, Execution, etc.
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    detection_guidance = Column(Text, nullable=True)


class IncidentTechnique(Base):
    __tablename__ = "incident_techniques"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    technique_id = Column(String(50), ForeignKey("attack_techniques.id"), nullable=False)
    supporting_behavior = Column(Text, nullable=False)
    evidence_reference = Column(Text, nullable=True)
    confidence = Column(Float, default=0.85)
    is_confirmed = Column(Boolean, default=True) # True=confirmed, False=hypothetical

    incident = relationship("Incident", back_populates="techniques")
    technique = relationship("AttackTechnique")


class IOA(Base):
    __tablename__ = "indicators_of_attack"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False, index=True)
    ioa_type = Column(String(100), nullable=False, index=True) # EXECUTION, PERSISTENCE, CREDENTIAL_ACCESS, DEFENSE_EVASION, LATERAL_MOVEMENT, C2, EXFILTRATION
    pattern_name = Column(String(300), nullable=False) # e.g., 'PowerShell Obfuscated Download Cradle'
    technique_id = Column(String(50), nullable=True, index=True) # e.g., 'T1059.001'
    observed_behavior = Column(Text, nullable=False) # Concrete action taken by the attacker
    detection_logic = Column(Text, nullable=True) # Behavioral detection guidance or rule
    evidence_quote = Column(Text, nullable=True) # Direct source citation
    confidence = Column(Float, default=0.9)
    created_at = Column(DateTime, default=utc_now)

    incident = relationship("Incident", back_populates="ioas")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    event_timestamp = Column(DateTime, nullable=True)
    event_order = Column(Integer, default=0)
    stage = Column(String(100), nullable=True)
    description = Column(Text, nullable=False)
    evidence_passage = Column(Text, nullable=True)

    incident = relationship("Incident", back_populates="timeline_events")


class MitigationRecommendation(Base):
    __tablename__ = "mitigation_recommendations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    category = Column(String(50), nullable=False) # IMMEDIATE, SHORT_TERM, PREVENTIVE, DETECTION, LONG_TERM
    title = Column(String(300), nullable=False)
    action_items = Column(Text, nullable=False)
    priority = Column(String(20), default="HIGH") # URGENT, HIGH, MEDIUM, LOW
    implementation_effort = Column(String(20), default="MEDIUM") # LOW, MEDIUM, HIGH

    incident = relationship("Incident", back_populates="recommendations")


class HistoricalCorrelation(Base):
    __tablename__ = "historical_correlations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    correlated_incident_id = Column(String(36), nullable=False)
    correlation_type = Column(String(50), nullable=False) # SHARED_IOC, SHARED_CVE, SIMILAR_TTP, VECTOR_SIMILARITY
    match_details = Column(Text, nullable=False)
    similarity_score = Column(Float, default=0.0)

    incident = relationship("Incident", back_populates="correlations")


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True)
    agent_name = Column(String(100), nullable=False)
    status = Column(String(50), default="RUNNING") # RUNNING, COMPLETED, FAILED, RETRIED
    inputs = Column(Text, nullable=True) # JSON
    outputs = Column(Text, nullable=True) # JSON
    decision_summary = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, default=utc_now)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0.0)

    incident = relationship("Incident", back_populates="agent_runs")
    tool_executions = relationship("ToolExecution", back_populates="agent_run", cascade="all, delete-orphan")


class ToolExecution(Base):
    __tablename__ = "tool_executions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    agent_run_id = Column(String(36), ForeignKey("agent_runs.id"), nullable=False)
    tool_name = Column(String(100), nullable=False)
    input_params = Column(Text, nullable=True) # JSON
    output_data = Column(Text, nullable=True) # JSON
    status = Column(String(20), default="SUCCESS") # SUCCESS, ERROR
    started_at = Column(DateTime, default=utc_now)
    completed_at = Column(DateTime, nullable=True)

    agent_run = relationship("AgentRun", back_populates="tool_executions")


class VerificationReview(Base):
    __tablename__ = "verification_reviews"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    status = Column(String(50), nullable=False) # APPROVED, REJECTED, NEEDS_CORRECTION
    review_score = Column(Float, default=1.0) # 0.0 to 1.0
    accepted_findings = Column(Text, nullable=True) # JSON
    rejected_findings = Column(Text, nullable=True) # JSON
    rejection_reasons = Column(Text, nullable=True) # JSON
    unsupported_claims = Column(Text, nullable=True) # JSON
    reviewed_at = Column(DateTime, default=utc_now)

    incident = relationship("Incident", back_populates="verification_reviews")


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True)
    notification_type = Column(String(50), nullable=False) # DISCOVERY, INCIDENT_REPORT, NEW_IOC, DIGEST, TEST
    recipient = Column(String(200), nullable=False)
    subject = Column(String(500), nullable=False)
    html_content = Column(Text, nullable=False)
    plain_text_content = Column(Text, nullable=False)
    delivery_status = Column(String(50), default="PENDING") # PENDING, SENT, FAILED, PERMANENTLY_FAILED, PREVIEW_ONLY
    idempotency_key = Column(String(100), unique=True, index=True)
    attempt_count = Column(Integer, default=0)
    last_attempt_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    message_id = Column(String(200), nullable=True) # Gmail Message ID
    created_at = Column(DateTime, default=utc_now)

    incident = relationship("Incident", back_populates="notifications")


class AnalystPreference(Base):
    __tablename__ = "analyst_preferences"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    preference_key = Column(String(100), unique=True, nullable=False)
    preference_value = Column(Text, nullable=False) # JSON or string
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)
