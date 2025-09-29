from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ControlType(str, Enum):
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    DIRECTIVE = "directive"


class ThreatCategory(str, Enum):
    INJECTION = "injection"
    BROKEN_AUTH = "broken_authentication"
    SENSITIVE_DATA = "sensitive_data_exposure"
    XML_EXTERNAL = "xml_external_entities"
    BROKEN_ACCESS = "broken_access_control"
    SECURITY_MISCONFIG = "security_misconfiguration"
    XSS = "cross_site_scripting"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    KNOWN_VULNERABILITIES = "known_vulnerabilities"
    INSUFFICIENT_LOGGING = "insufficient_logging"


class SecurityControl(BaseModel):
    """Security control model for OpenSearch vector storage"""
    id: str
    name: str
    description: str
    control_type: ControlType
    framework: str  # e.g., "NIST", "ISO27001", "CIS"
    control_id: str  # Framework-specific ID
    implementation_guidance: str
    effectiveness_rating: float = Field(ge=0.0, le=1.0)
    cost_rating: float = Field(ge=0.0, le=1.0)  # 0=low cost, 1=high cost
    complexity_rating: float = Field(ge=0.0, le=1.0)  # 0=simple, 1=complex
    applicable_threats: List[ThreatCategory]
    applicable_architectures: List[str]  # e.g., ["web_app", "api", "microservices"]
    tags: List[str]
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ThreatIntelligence(BaseModel):
    """Threat intelligence model for OpenSearch vector storage"""
    id: str
    name: str
    description: str
    threat_category: ThreatCategory
    severity: SeverityLevel
    attack_vectors: List[str]
    affected_components: List[str]  # e.g., ["web_server", "database", "api_gateway"]
    indicators_of_compromise: List[str]
    mitigation_strategies: List[str]
    cve_references: List[str]
    mitre_attack_techniques: List[str]
    likelihood_score: float = Field(ge=0.0, le=1.0)
    impact_score: float = Field(ge=0.0, le=1.0)
    exploitability_score: float = Field(ge=0.0, le=1.0)
    applicable_architectures: List[str]
    tags: List[str]
    first_seen: datetime
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class Architecture(BaseModel):
    """System architecture model"""
    id: str
    name: str
    description: str
    components: List[str]
    data_flows: List[str]
    trust_boundaries: List[str]
    threat_model: Optional[str] = None
    compliance_requirements: List[str]
    tags: List[str]


class ThreatControlRelationship(BaseModel):
    """Relationship between threats and controls for graph storage"""
    threat_id: str
    control_id: str
    effectiveness: float = Field(ge=0.0, le=1.0)
    coverage_percentage: float = Field(ge=0.0, le=1.0)
    implementation_cost: str  # "low", "medium", "high"
    relationship_type: str  # "mitigates", "prevents", "detects"


class SearchResult(BaseModel):
    """Unified search result model"""
    item_id: str
    item_type: str  # "control", "threat", "architecture"
    name: str
    description: str
    score: float
    metadata: Dict[str, Any]
    relationships: Optional[List[Dict[str, Any]]] = None


class HybridSearchQuery(BaseModel):
    """Query model for hybrid search"""
    query_text: str
    architecture_type: Optional[str] = None
    threat_categories: Optional[List[ThreatCategory]] = None
    control_types: Optional[List[ControlType]] = None
    severity_filter: Optional[List[SeverityLevel]] = None
    max_results: int = Field(default=10, ge=1, le=100)
    include_relationships: bool = True
    semantic_weight: float = Field(default=0.7, ge=0.0, le=1.0)
    graph_weight: float = Field(default=0.3, ge=0.0, le=1.0)