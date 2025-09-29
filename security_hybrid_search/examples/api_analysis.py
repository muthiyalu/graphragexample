"""
API Security Analysis Examples

This module demonstrates API-specific security analysis including:
1. REST API security threats
2. GraphQL security considerations
3. Microservices security patterns
4. API gateway security controls
"""

from typing import List, Dict, Any
import json
from datetime import datetime

from models.security_models import HybridSearchQuery, ThreatCategory, ControlType, SeverityLevel
from services.hybrid_search import HybridSearchEngine


class APISecurityAnalyzer:
    """Security analyzer for API architectures"""
    
    def __init__(self, hybrid_search: HybridSearchEngine):
        self.search_engine = hybrid_search
    
    def analyze_rest_api_security(self) -> Dict[str, Any]:
        """Analyze REST API specific security threats and controls"""
        
        print("🔍 Analyzing REST API Security...")
        
        query = HybridSearchQuery(
            query_text="REST API authentication authorization rate limiting injection",
            architecture_type="api",
            threat_categories=[
                ThreatCategory.BROKEN_AUTH,
                ThreatCategory.BROKEN_ACCESS,
                ThreatCategory.INJECTION,
                ThreatCategory.SENSITIVE_DATA
            ],
            control_types=[ControlType.PREVENTIVE, ControlType.DETECTIVE],
            max_results=12,
            semantic_weight=0.7,
            graph_weight=0.3
        )
        
        results = self.search_engine.search(query)
        
        api_threats = [r for r in results if r.item_type == "threat"]
        api_controls = [r for r in results if r.item_type == "control"]
        
        return {
            "analysis_type": "REST API Security Analysis",
            "timestamp": datetime.utcnow().isoformat(),
            "api_type": "REST",
            "threat_summary": {
                "total_threats": len(api_threats),
                "critical_threats": len([t for t in api_threats 
                                       if t.metadata["source_data"].get("severity") == "critical"]),
                "authentication_threats": len([t for t in api_threats 
                                             if "authentication" in t.name.lower() or 
                                                "auth" in t.description.lower()]),
                "injection_threats": len([t for t in api_threats 
                                        if t.metadata["source_data"].get("threat_category") == "injection"])
            },
            "top_api_threats": [
                {
                    "name": t.name,
                    "category": t.metadata["source_data"].get("threat_category"),
                    "severity": t.metadata["source_data"].get("severity"),
                    "attack_vectors": t.metadata["source_data"].get("attack_vectors", []),
                    "score": t.score
                }
                for t in api_threats[:5]
            ],
            "recommended_controls": [
                {
                    "name": c.name,
                    "type": c.metadata["source_data"].get("control_type"),
                    "effectiveness": c.metadata["source_data"].get("effectiveness_rating"),
                    "implementation": c.metadata["source_data"].get("implementation_guidance", "")[:150] + "..."
                }
                for c in api_controls[:5]
            ]
        }
    
    def analyze_microservices_security(self) -> Dict[str, Any]:
        """Analyze microservices architecture security patterns"""
        
        print("🔍 Analyzing Microservices Security...")
        
        query = HybridSearchQuery(
            query_text="microservices service mesh authentication authorization communication security",
            architecture_type="microservices",
            threat_categories=[
                ThreatCategory.BROKEN_AUTH,
                ThreatCategory.BROKEN_ACCESS,
                ThreatCategory.SECURITY_MISCONFIG,
                ThreatCategory.INSUFFICIENT_LOGGING
            ],
            max_results=15
        )
        
        results = self.search_engine.search(query)
        
        # Get specific microservices recommendations
        control_recommendations = self.search_engine.recommend_controls_for_architecture(
            "microservices", max_results=8
        )
        
        return {
            "analysis_type": "Microservices Security Analysis",
            "timestamp": datetime.utcnow().isoformat(),
            "architecture": "microservices",
            "security_domains": {
                "service_communication": self._analyze_service_communication_security(),
                "authentication_authorization": self._analyze_microservices_auth(),
                "data_protection": self._analyze_microservices_data_protection(),
                "monitoring_logging": self._analyze_microservices_monitoring()
            },
            "control_recommendations": [
                {
                    "name": rec.name,
                    "effectiveness": rec.score,
                    "threat_coverage": rec.metadata.get("threat_coverage", 0),
                    "mitigated_threats": rec.metadata.get("mitigated_threats", [])
                }
                for rec in control_recommendations
            ]
        }
    
    def _analyze_service_communication_security(self) -> Dict[str, Any]:
        """Analyze service-to-service communication security"""
        
        query = HybridSearchQuery(
            query_text="service mesh mTLS encryption inter-service communication",
            architecture_type="microservices",
            max_results=5
        )
        
        results = self.search_engine.search(query)
        
        return {
            "threats_identified": len([r for r in results if r.item_type == "threat"]),
            "controls_available": len([r for r in results if r.item_type == "control"]),
            "key_concerns": [
                "Man-in-the-middle attacks on service communication",
                "Unencrypted inter-service traffic",
                "Service identity verification",
                "Certificate management complexity"
            ]
        }
    
    def _analyze_microservices_auth(self) -> Dict[str, Any]:
        """Analyze microservices authentication and authorization"""
        
        return {
            "authentication_patterns": [
                "JWT tokens for stateless authentication",
                "OAuth 2.0 for external API access",
                "Service accounts for inter-service calls"
            ],
            "authorization_models": [
                "Role-Based Access Control (RBAC)",
                "Attribute-Based Access Control (ABAC)",
                "Zero Trust security model"
            ],
            "key_challenges": [
                "Token propagation across services",
                "Centralized vs. distributed authorization",
                "Service-to-service trust establishment"
            ]
        }
    
    def _analyze_microservices_data_protection(self) -> Dict[str, Any]:
        """Analyze data protection in microservices"""
        
        return {
            "data_concerns": [
                "Data in transit encryption",
                "Data at rest protection",
                "Sensitive data isolation",
                "Data sovereignty compliance"
            ],
            "protection_strategies": [
                "End-to-end encryption",
                "Database-level encryption",
                "Secrets management systems",
                "Data classification and labeling"
            ]
        }
    
    def _analyze_microservices_monitoring(self) -> Dict[str, Any]:
        """Analyze monitoring and logging for microservices"""
        
        return {
            "monitoring_requirements": [
                "Distributed tracing",
                "Centralized logging",
                "Security event correlation",
                "Real-time threat detection"
            ],
            "key_metrics": [
                "Authentication failure rates",
                "Unauthorized access attempts",
                "Service communication anomalies",
                "Data access patterns"
            ]
        }


def demonstrate_api_analysis():
    """Demonstrate API security analysis"""
    
    print("🚀 Starting API Security Analysis Demo")
    print("=" * 50)
    
    # This would normally initialize with actual database connections
    print("Note: This demo shows the analysis structure.")
    print("In a real implementation, connect to OpenSearch and Neo4j first.\n")
    
    # Mock analysis results for demonstration
    rest_analysis = {
        "analysis_type": "REST API Security Analysis",
        "timestamp": datetime.utcnow().isoformat(),
        "api_type": "REST",
        "threat_summary": {
            "total_threats": 12,
            "critical_threats": 3,
            "authentication_threats": 4,
            "injection_threats": 2
        },
        "top_api_threats": [
            {
                "name": "Broken Authentication",
                "category": "broken_authentication",
                "severity": "critical",
                "attack_vectors": ["credential stuffing", "session hijacking"],
                "score": 0.95
            },
            {
                "name": "API Injection",
                "category": "injection",
                "severity": "high",
                "attack_vectors": ["SQL injection", "NoSQL injection"],
                "score": 0.87
            }
        ]
    }
    
    microservices_analysis = {
        "analysis_type": "Microservices Security Analysis",
        "timestamp": datetime.utcnow().isoformat(),
        "architecture": "microservices",
        "security_domains": {
            "service_communication": {
                "threats_identified": 5,
                "controls_available": 8,
                "key_concerns": [
                    "Man-in-the-middle attacks on service communication",
                    "Unencrypted inter-service traffic"
                ]
            }
        }
    }
    
    print("1. REST API Security Analysis")
    print("-" * 30)
    print(json.dumps(rest_analysis, indent=2, default=str))
    
    print("\n2. Microservices Security Analysis")
    print("-" * 35)
    print(json.dumps(microservices_analysis, indent=2, default=str))


if __name__ == "__main__":
    demonstrate_api_analysis()