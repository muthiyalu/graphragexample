import os
from typing import List, Dict, Any, Optional, Tuple
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError
import json
from datetime import datetime

from models.security_models import (
    SecurityControl, ThreatIntelligence, Architecture, 
    ThreatControlRelationship, ThreatCategory, ControlType
)


class Neo4jClient:
    """Neo4j client for graph-based relationship queries"""
    
    def __init__(self):
        self.uri = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
        self.username = os.getenv('NEO4J_USERNAME', 'neo4j')
        self.password = os.getenv('NEO4J_PASSWORD', 'password')
        
        self.driver = GraphDatabase.driver(
            self.uri, 
            auth=(self.username, self.password)
        )
        
        self._create_constraints_and_indices()
    
    def close(self):
        """Close the Neo4j driver"""
        self.driver.close()
    
    def _create_constraints_and_indices(self):
        """Create constraints and indices for better performance"""
        with self.driver.session() as session:
            # Create uniqueness constraints
            session.run("CREATE CONSTRAINT control_id_unique IF NOT EXISTS FOR (c:Control) REQUIRE c.id IS UNIQUE")
            session.run("CREATE CONSTRAINT threat_id_unique IF NOT EXISTS FOR (t:Threat) REQUIRE t.id IS UNIQUE")
            session.run("CREATE CONSTRAINT architecture_id_unique IF NOT EXISTS FOR (a:Architecture) REQUIRE a.id IS UNIQUE")
            
            # Create indices for common queries
            session.run("CREATE INDEX control_category_idx IF NOT EXISTS FOR (c:Control) ON (c.control_type)")
            session.run("CREATE INDEX threat_category_idx IF NOT EXISTS FOR (t:Threat) ON (t.threat_category)")
            session.run("CREATE INDEX threat_severity_idx IF NOT EXISTS FOR (t:Threat) ON (t.severity)")
            session.run("CREATE INDEX architecture_type_idx IF NOT EXISTS FOR (a:Architecture) ON (a.architecture_type)")
    
    def create_security_control_node(self, control: SecurityControl) -> bool:
        """Create a security control node in Neo4j"""
        query = """
        MERGE (c:Control {id: $id})
        SET c.name = $name,
            c.description = $description,
            c.control_type = $control_type,
            c.framework = $framework,
            c.control_id = $control_id,
            c.implementation_guidance = $implementation_guidance,
            c.effectiveness_rating = $effectiveness_rating,
            c.cost_rating = $cost_rating,
            c.complexity_rating = $complexity_rating,
            c.applicable_threats = $applicable_threats,
            c.applicable_architectures = $applicable_architectures,
            c.tags = $tags,
            c.created_at = $created_at,
            c.updated_at = $updated_at
        RETURN c.id
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {
                    "id": control.id,
                    "name": control.name,
                    "description": control.description,
                    "control_type": control.control_type.value,
                    "framework": control.framework,
                    "control_id": control.control_id,
                    "implementation_guidance": control.implementation_guidance,
                    "effectiveness_rating": control.effectiveness_rating,
                    "cost_rating": control.cost_rating,
                    "complexity_rating": control.complexity_rating,
                    "applicable_threats": [t.value for t in control.applicable_threats],
                    "applicable_architectures": control.applicable_architectures,
                    "tags": control.tags,
                    "created_at": control.created_at.isoformat(),
                    "updated_at": control.updated_at.isoformat()
                })
                return bool(result.single())
        except Exception as e:
            print(f"Error creating control node {control.id}: {e}")
            return False
    
    def create_threat_intelligence_node(self, threat: ThreatIntelligence) -> bool:
        """Create a threat intelligence node in Neo4j"""
        query = """
        MERGE (t:Threat {id: $id})
        SET t.name = $name,
            t.description = $description,
            t.threat_category = $threat_category,
            t.severity = $severity,
            t.attack_vectors = $attack_vectors,
            t.affected_components = $affected_components,
            t.indicators_of_compromise = $indicators_of_compromise,
            t.mitigation_strategies = $mitigation_strategies,
            t.cve_references = $cve_references,
            t.mitre_attack_techniques = $mitre_attack_techniques,
            t.likelihood_score = $likelihood_score,
            t.impact_score = $impact_score,
            t.exploitability_score = $exploitability_score,
            t.applicable_architectures = $applicable_architectures,
            t.tags = $tags,
            t.first_seen = $first_seen,
            t.last_updated = $last_updated
        RETURN t.id
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {
                    "id": threat.id,
                    "name": threat.name,
                    "description": threat.description,
                    "threat_category": threat.threat_category.value,
                    "severity": threat.severity.value,
                    "attack_vectors": threat.attack_vectors,
                    "affected_components": threat.affected_components,
                    "indicators_of_compromise": threat.indicators_of_compromise,
                    "mitigation_strategies": threat.mitigation_strategies,
                    "cve_references": threat.cve_references,
                    "mitre_attack_techniques": threat.mitre_attack_techniques,
                    "likelihood_score": threat.likelihood_score,
                    "impact_score": threat.impact_score,
                    "exploitability_score": threat.exploitability_score,
                    "applicable_architectures": threat.applicable_architectures,
                    "tags": threat.tags,
                    "first_seen": threat.first_seen.isoformat(),
                    "last_updated": threat.last_updated.isoformat()
                })
                return bool(result.single())
        except Exception as e:
            print(f"Error creating threat node {threat.id}: {e}")
            return False
    
    def create_architecture_node(self, architecture: Architecture) -> bool:
        """Create an architecture node in Neo4j"""
        query = """
        MERGE (a:Architecture {id: $id})
        SET a.name = $name,
            a.description = $description,
            a.components = $components,
            a.data_flows = $data_flows,
            a.trust_boundaries = $trust_boundaries,
            a.threat_model = $threat_model,
            a.compliance_requirements = $compliance_requirements,
            a.tags = $tags
        RETURN a.id
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {
                    "id": architecture.id,
                    "name": architecture.name,
                    "description": architecture.description,
                    "components": architecture.components,
                    "data_flows": architecture.data_flows,
                    "trust_boundaries": architecture.trust_boundaries,
                    "threat_model": architecture.threat_model,
                    "compliance_requirements": architecture.compliance_requirements,
                    "tags": architecture.tags
                })
                return bool(result.single())
        except Exception as e:
            print(f"Error creating architecture node {architecture.id}: {e}")
            return False
    
    def create_threat_control_relationship(
        self, 
        threat_id: str, 
        control_id: str, 
        relationship: ThreatControlRelationship
    ) -> bool:
        """Create relationship between threat and control"""
        query = """
        MATCH (t:Threat {id: $threat_id})
        MATCH (c:Control {id: $control_id})
        MERGE (c)-[r:MITIGATES]->(t)
        SET r.effectiveness = $effectiveness,
            r.coverage_percentage = $coverage_percentage,
            r.implementation_cost = $implementation_cost,
            r.relationship_type = $relationship_type
        RETURN r
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {
                    "threat_id": threat_id,
                    "control_id": control_id,
                    "effectiveness": relationship.effectiveness,
                    "coverage_percentage": relationship.coverage_percentage,
                    "implementation_cost": relationship.implementation_cost,
                    "relationship_type": relationship.relationship_type
                })
                return bool(result.single())
        except Exception as e:
            print(f"Error creating relationship {control_id} -> {threat_id}: {e}")
            return False
    
    def find_controls_for_threat(self, threat_id: str) -> List[Dict[str, Any]]:
        """Find all controls that mitigate a specific threat"""
        query = """
        MATCH (c:Control)-[r:MITIGATES]->(t:Threat {id: $threat_id})
        RETURN c, r
        ORDER BY r.effectiveness DESC, r.coverage_percentage DESC
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {"threat_id": threat_id})
                return [
                    {
                        "control": dict(record["c"]),
                        "relationship": dict(record["r"])
                    }
                    for record in result
                ]
        except Exception as e:
            print(f"Error finding controls for threat {threat_id}: {e}")
            return []
    
    def find_threats_for_control(self, control_id: str) -> List[Dict[str, Any]]:
        """Find all threats mitigated by a specific control"""
        query = """
        MATCH (c:Control {id: $control_id})-[r:MITIGATES]->(t:Threat)
        RETURN t, r
        ORDER BY t.severity, r.effectiveness DESC
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {"control_id": control_id})
                return [
                    {
                        "threat": dict(record["t"]),
                        "relationship": dict(record["r"])
                    }
                    for record in result
                ]
        except Exception as e:
            print(f"Error finding threats for control {control_id}: {e}")
            return []
    
    def find_controls_for_architecture(self, architecture_type: str) -> List[Dict[str, Any]]:
        """Find relevant controls for a specific architecture"""
        query = """
        MATCH (c:Control)
        WHERE $architecture_type IN c.applicable_architectures
        RETURN c
        ORDER BY c.effectiveness_rating DESC
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {"architecture_type": architecture_type})
                return [dict(record["c"]) for record in result]
        except Exception as e:
            print(f"Error finding controls for architecture {architecture_type}: {e}")
            return []
    
    def find_threats_for_architecture(self, architecture_type: str) -> List[Dict[str, Any]]:
        """Find relevant threats for a specific architecture"""
        query = """
        MATCH (t:Threat)
        WHERE $architecture_type IN t.applicable_architectures
        RETURN t
        ORDER BY t.severity, t.likelihood_score DESC, t.impact_score DESC
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {"architecture_type": architecture_type})
                return [dict(record["t"]) for record in result]
        except Exception as e:
            print(f"Error finding threats for architecture {architecture_type}: {e}")
            return []
    
    def find_threat_chains(self, start_threat_id: str, max_depth: int = 3) -> List[Dict[str, Any]]:
        """Find threat chains and attack paths"""
        query = """
        MATCH path = (start:Threat {id: $start_threat_id})-[:LEADS_TO*1..$max_depth]->(end:Threat)
        RETURN path, 
               length(path) as chain_length,
               [threat in nodes(path) | threat.name] as threat_names
        ORDER BY chain_length, end.severity
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {
                    "start_threat_id": start_threat_id,
                    "max_depth": max_depth
                })
                return [
                    {
                        "path": record["path"],
                        "chain_length": record["chain_length"],
                        "threat_names": record["threat_names"]
                    }
                    for record in result
                ]
        except Exception as e:
            print(f"Error finding threat chains for {start_threat_id}: {e}")
            return []
    
    def find_control_gaps(self, architecture_type: str) -> List[Dict[str, Any]]:
        """Find threats without adequate controls for an architecture"""
        query = """
        MATCH (t:Threat)
        WHERE $architecture_type IN t.applicable_architectures
        OPTIONAL MATCH (c:Control)-[r:MITIGATES]->(t)
        WHERE $architecture_type IN c.applicable_architectures
        WITH t, collect(r) as relationships
        WHERE size(relationships) = 0 OR all(rel in relationships WHERE rel.effectiveness < 0.7)
        RETURN t,
               size(relationships) as control_count,
               [rel in relationships | rel.effectiveness] as effectiveness_scores
        ORDER BY t.severity, t.likelihood_score DESC
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {"architecture_type": architecture_type})
                return [
                    {
                        "threat": dict(record["t"]),
                        "control_count": record["control_count"],
                        "effectiveness_scores": record["effectiveness_scores"]
                    }
                    for record in result
                ]
        except Exception as e:
            print(f"Error finding control gaps for {architecture_type}: {e}")
            return []
    
    def recommend_controls_for_threats(
        self, 
        threat_ids: List[str], 
        architecture_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Recommend controls for multiple threats"""
        threat_filter = "t.id IN $threat_ids"
        arch_filter = ""
        
        if architecture_type:
            arch_filter = "AND $architecture_type IN c.applicable_architectures"
        
        query = f"""
        MATCH (t:Threat)
        WHERE {threat_filter}
        MATCH (c:Control)-[r:MITIGATES]->(t)
        WHERE r.effectiveness >= 0.5 {arch_filter}
        RETURN c, 
               collect({{threat_id: t.id, threat_name: t.name, effectiveness: r.effectiveness}}) as mitigated_threats,
               avg(r.effectiveness) as avg_effectiveness,
               count(t) as threat_coverage
        ORDER BY threat_coverage DESC, avg_effectiveness DESC
        """
        
        params = {"threat_ids": threat_ids}
        if architecture_type:
            params["architecture_type"] = architecture_type
        
        try:
            with self.driver.session() as session:
                result = session.run(query, params)
                return [
                    {
                        "control": dict(record["c"]),
                        "mitigated_threats": record["mitigated_threats"],
                        "avg_effectiveness": record["avg_effectiveness"],
                        "threat_coverage": record["threat_coverage"]
                    }
                    for record in result
                ]
        except Exception as e:
            print(f"Error recommending controls for threats: {e}")
            return []
    
    def get_threat_landscape_summary(self, architecture_type: str) -> Dict[str, Any]:
        """Get threat landscape summary for an architecture"""
        query = """
        MATCH (t:Threat)
        WHERE $architecture_type IN t.applicable_architectures
        OPTIONAL MATCH (c:Control)-[r:MITIGATES]->(t)
        WHERE $architecture_type IN c.applicable_architectures
        RETURN 
            count(DISTINCT t) as total_threats,
            count(DISTINCT c) as total_controls,
            count(DISTINCT r) as total_relationships,
            collect(DISTINCT t.threat_category) as threat_categories,
            collect(DISTINCT t.severity) as severity_levels,
            avg(t.likelihood_score) as avg_likelihood,
            avg(t.impact_score) as avg_impact
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {"architecture_type": architecture_type})
                record = result.single()
                if record:
                    return dict(record)
                return {}
        except Exception as e:
            print(f"Error getting threat landscape summary: {e}")
            return {}