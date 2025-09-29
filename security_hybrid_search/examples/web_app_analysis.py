"""
Web Application Security Analysis Examples

This module demonstrates how to use the hybrid search system for:
1. Analyzing threats for web application architectures
2. Providing security control recommendations
3. Identifying security gaps and vulnerabilities
"""

from typing import List, Dict, Any
import json
from datetime import datetime

from models.security_models import HybridSearchQuery, ThreatCategory, ControlType, SeverityLevel
from services.hybrid_search import HybridSearchEngine
from database.opensearch_client import OpenSearchClient
from database.neo4j_client import Neo4jClient


class WebAppSecurityAnalyzer:
    """Security analyzer for web application architectures"""
    
    def __init__(self, hybrid_search: HybridSearchEngine):
        self.search_engine = hybrid_search
    
    def analyze_web_app_threats(self) -> Dict[str, Any]:
        """Analyze threats specific to web applications"""
        
        print("🔍 Analyzing Web Application Threats...")
        
        # Create query for web app threats
        query = HybridSearchQuery(
            query_text="web application vulnerabilities injection XSS authentication",
            architecture_type="web_app",
            threat_categories=[
                ThreatCategory.INJECTION,
                ThreatCategory.XSS,
                ThreatCategory.BROKEN_AUTH,
                ThreatCategory.BROKEN_ACCESS
            ],
            severity_filter=[SeverityLevel.CRITICAL, SeverityLevel.HIGH],
            max_results=15,
            semantic_weight=0.6,
            graph_weight=0.4
        )
        
        # Perform hybrid search
        results = self.search_engine.search(query)
        
        # Categorize results
        threats = [r for r in results if r.item_type == "threat"]
        controls = [r for r in results if r.item_type == "control"]
        
        analysis = {
            "analysis_type": "Web Application Threat Analysis",
            "timestamp": datetime.utcnow().isoformat(),
            "architecture": "web_app",
            "summary": {
                "total_threats_found": len(threats),
                "total_controls_found": len(controls),
                "avg_threat_score": sum(t.score for t in threats) / len(threats) if threats else 0,
                "high_priority_threats": len([t for t in threats if t.score > 0.7])
            },
            "top_threats": [],
            "recommended_controls": [],
            "threat_categories_coverage": {}
        }
        
        # Analyze top threats
        for threat in threats[:5]:
            threat_info = {
                "id": threat.item_id,
                "name": threat.name,
                "description": threat.description,
                "score": threat.score,
                "severity": threat.metadata["source_data"].get("severity"),
                "category": threat.metadata["source_data"].get("threat_category"),
                "attack_vectors": threat.metadata["source_data"].get("attack_vectors", []),
                "mitigating_controls": len(threat.relationships) if threat.relationships else 0,
                "has_control_gap": threat.metadata.get("control_gap", False)
            }
            analysis["top_threats"].append(threat_info)
        
        # Analyze recommended controls
        for control in controls[:5]:
            control_info = {
                "id": control.item_id,
                "name": control.name,
                "description": control.description,
                "score": control.score,
                "type": control.metadata["source_data"].get("control_type"),
                "framework": control.metadata["source_data"].get("framework"),
                "effectiveness": control.metadata["source_data"].get("effectiveness_rating"),
                "cost": control.metadata["source_data"].get("cost_rating"),
                "complexity": control.metadata["source_data"].get("complexity_rating")
            }
            analysis["recommended_controls"].append(control_info)
        
        return analysis
    
    def get_owasp_top10_analysis(self) -> Dict[str, Any]:
        """Analyze threats based on OWASP Top 10"""
        
        print("🔍 Analyzing OWASP Top 10 Threats for Web Apps...")
        
        owasp_categories = [
            ThreatCategory.INJECTION,
            ThreatCategory.BROKEN_AUTH,
            ThreatCategory.SENSITIVE_DATA,
            ThreatCategory.XML_EXTERNAL,
            ThreatCategory.BROKEN_ACCESS,
            ThreatCategory.SECURITY_MISCONFIG,
            ThreatCategory.XSS,
            ThreatCategory.INSECURE_DESERIALIZATION,
            ThreatCategory.KNOWN_VULNERABILITIES,
            ThreatCategory.INSUFFICIENT_LOGGING
        ]
        
        analysis = {
            "analysis_type": "OWASP Top 10 Analysis",
            "timestamp": datetime.utcnow().isoformat(),
            "categories": []
        }
        
        for category in owasp_categories:
            # Search for threats in this category
            query = HybridSearchQuery(
                query_text=f"{category.value} web application security",
                architecture_type="web_app",
                threat_categories=[category],
                max_results=5,
                include_relationships=True
            )
            
            results = self.search_engine.search(query)
            threats = [r for r in results if r.item_type == "threat"]
            
            category_analysis = {
                "category": category.value,
                "threat_count": len(threats),
                "avg_score": sum(t.score for t in threats) / len(threats) if threats else 0,
                "threats": []
            }
            
            for threat in threats:
                threat_data = {
                    "name": threat.name,
                    "severity": threat.metadata["source_data"].get("severity"),
                    "likelihood": threat.metadata["source_data"].get("likelihood_score"),
                    "impact": threat.metadata["source_data"].get("impact_score"),
                    "control_count": len(threat.relationships) if threat.relationships else 0
                }
                category_analysis["threats"].append(threat_data)
            
            analysis["categories"].append(category_analysis)
        
        return analysis
    
    def recommend_security_framework(self, compliance_requirements: List[str] = None) -> Dict[str, Any]:
        """Recommend security controls based on frameworks"""
        
        print("🔍 Recommending Security Framework Controls...")
        
        frameworks = ["NIST", "ISO27001", "CIS", "OWASP"]
        recommendations = {}
        
        for framework in frameworks:
            query = HybridSearchQuery(
                query_text=f"{framework} web application security controls",
                architecture_type="web_app",
                control_types=[ControlType.PREVENTIVE, ControlType.DETECTIVE],
                max_results=10
            )
            
            results = self.search_engine.search(query)
            controls = [r for r in results if r.item_type == "control" 
                       and r.metadata["source_data"].get("framework") == framework]
            
            framework_rec = {
                "framework": framework,
                "control_count": len(controls),
                "avg_effectiveness": sum(c.metadata["source_data"].get("effectiveness_rating", 0) 
                                       for c in controls) / len(controls) if controls else 0,
                "controls": []
            }
            
            for control in controls[:5]:
                control_data = {
                    "name": control.name,
                    "control_id": control.metadata["source_data"].get("control_id"),
                    "type": control.metadata["source_data"].get("control_type"),
                    "effectiveness": control.metadata["source_data"].get("effectiveness_rating"),
                    "implementation_guidance": control.metadata["source_data"].get("implementation_guidance", "")[:200] + "..."
                }
                framework_rec["controls"].append(control_data)
            
            recommendations[framework] = framework_rec
        
        return {
            "analysis_type": "Security Framework Recommendations",
            "timestamp": datetime.utcnow().isoformat(),
            "architecture": "web_app",
            "frameworks": recommendations
        }
    
    def identify_security_gaps(self) -> Dict[str, Any]:
        """Identify security gaps in web application architecture"""
        
        print("🔍 Identifying Security Gaps...")
        
        # Get threat landscape analysis
        landscape = self.search_engine.analyze_threat_landscape("web_app")
        
        # Find high-priority gaps
        priority_threats = []
        for gap in landscape.get("recommendations", {}).get("priority_gaps", []):
            threat = gap["threat"]
            priority_threats.append({
                "name": threat["name"],
                "severity": threat["severity"],
                "category": threat["threat_category"],
                "likelihood": threat.get("likelihood_score", 0),
                "impact": threat.get("impact_score", 0),
                "control_count": gap["control_count"],
                "risk_level": self._calculate_risk_level(threat)
            })
        
        # Get control recommendations
        control_recommendations = landscape.get("recommendations", {}).get("suggested_controls", [])
        
        gap_analysis = {
            "analysis_type": "Security Gap Analysis",
            "timestamp": datetime.utcnow().isoformat(),
            "architecture": "web_app",
            "summary": {
                "total_gaps": landscape.get("control_gaps", 0),
                "high_risk_gaps": len([t for t in priority_threats if t["risk_level"] == "HIGH"]),
                "risk_score": landscape.get("risk_score", 0)
            },
            "priority_gaps": priority_threats,
            "control_recommendations": [
                {
                    "name": rec.name,
                    "effectiveness": rec.score,
                    "threat_coverage": rec.metadata.get("threat_coverage", 0),
                    "cost_estimate": self._estimate_implementation_cost(rec)
                }
                for rec in control_recommendations
            ]
        }
        
        return gap_analysis
    
    def _calculate_risk_level(self, threat: Dict[str, Any]) -> str:
        """Calculate risk level for a threat"""
        severity_weight = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1
        }
        
        severity_score = severity_weight.get(threat.get("severity", "low"), 1)
        likelihood = threat.get("likelihood_score", 0.5)
        impact = threat.get("impact_score", 0.5)
        
        risk_score = severity_score * (likelihood + impact) / 2
        
        if risk_score >= 4:
            return "HIGH"
        elif risk_score >= 2.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _estimate_implementation_cost(self, control) -> str:
        """Estimate implementation cost for a control"""
        cost_rating = control.metadata.get("source_data", {}).get("cost_rating", 0.5)
        complexity_rating = control.metadata.get("source_data", {}).get("complexity_rating", 0.5)
        
        combined_cost = (cost_rating + complexity_rating) / 2
        
        if combined_cost >= 0.7:
            return "HIGH"
        elif combined_cost >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"


def demonstrate_web_app_analysis():
    """Demonstrate web application security analysis"""
    
    print("🚀 Starting Web Application Security Analysis Demo")
    print("=" * 60)
    
    # Initialize clients (in real scenario, these would connect to actual databases)
    print("Initializing database connections...")
    opensearch_client = OpenSearchClient()
    neo4j_client = Neo4jClient()
    hybrid_search = HybridSearchEngine(opensearch_client, neo4j_client)
    
    # Initialize analyzer
    analyzer = WebAppSecurityAnalyzer(hybrid_search)
    
    try:
        # Perform different types of analysis
        print("\n1. General Web Application Threat Analysis")
        print("-" * 40)
        threat_analysis = analyzer.analyze_web_app_threats()
        print(json.dumps(threat_analysis, indent=2, default=str))
        
        print("\n2. OWASP Top 10 Analysis")
        print("-" * 40)
        owasp_analysis = analyzer.get_owasp_top10_analysis()
        print(json.dumps(owasp_analysis, indent=2, default=str))
        
        print("\n3. Security Framework Recommendations")
        print("-" * 40)
        framework_recs = analyzer.recommend_security_framework()
        print(json.dumps(framework_recs, indent=2, default=str))
        
        print("\n4. Security Gap Analysis")
        print("-" * 40)
        gap_analysis = analyzer.identify_security_gaps()
        print(json.dumps(gap_analysis, indent=2, default=str))
        
    except Exception as e:
        print(f"⚠️ Error during analysis: {e}")
        print("Note: This demo requires OpenSearch and Neo4j to be running with sample data.")
    
    finally:
        neo4j_client.close()


if __name__ == "__main__":
    demonstrate_web_app_analysis()