from typing import List, Dict, Any, Optional, Tuple
import asyncio
from dataclasses import dataclass
import numpy as np

from models.security_models import (
    HybridSearchQuery, SearchResult, SecurityControl, ThreatIntelligence,
    ThreatCategory, ControlType, SeverityLevel
)
from database.opensearch_client import OpenSearchClient
from database.neo4j_client import Neo4jClient


@dataclass
class HybridSearchConfig:
    """Configuration for hybrid search"""
    semantic_weight: float = 0.7
    graph_weight: float = 0.3
    min_semantic_score: float = 0.3
    min_graph_score: float = 0.1
    max_results_per_source: int = 20
    enable_result_fusion: bool = True


class HybridSearchEngine:
    """Hybrid search engine combining OpenSearch vector search with Neo4j graph queries"""
    
    def __init__(self, opensearch_client: OpenSearchClient, neo4j_client: Neo4jClient):
        self.opensearch = opensearch_client
        self.neo4j = neo4j_client
        self.config = HybridSearchConfig()
    
    def search(self, query: HybridSearchQuery) -> List[SearchResult]:
        """Perform hybrid search combining semantic and graph-based results"""
        
        # Update weights if provided in query
        semantic_weight = query.semantic_weight
        graph_weight = query.graph_weight
        
        # Normalize weights
        total_weight = semantic_weight + graph_weight
        if total_weight > 0:
            semantic_weight = semantic_weight / total_weight
            graph_weight = graph_weight / total_weight
        
        # Perform semantic search
        semantic_results = self._perform_semantic_search(query)
        
        # Perform graph-based search
        graph_results = self._perform_graph_search(query)
        
        # Combine and rank results
        combined_results = self._combine_results(
            semantic_results, 
            graph_results,
            semantic_weight,
            graph_weight
        )
        
        # Apply final filtering and ranking
        final_results = self._post_process_results(combined_results, query)
        
        return final_results[:query.max_results]
    
    def _perform_semantic_search(self, query: HybridSearchQuery) -> Dict[str, List[Dict[str, Any]]]:
        """Perform semantic search using OpenSearch"""
        results = {"controls": [], "threats": []}
        
        # Build filters for OpenSearch
        filters = {}
        
        if query.threat_categories:
            filters["threat_category"] = [cat.value for cat in query.threat_categories]
        
        if query.control_types:
            filters["control_type"] = [ct.value for ct in query.control_types]
        
        if query.severity_filter:
            filters["severity"] = [sev.value for sev in query.severity_filter]
        
        if query.architecture_type:
            filters["applicable_architectures"] = query.architecture_type
        
        # Search controls
        control_results = self.opensearch.semantic_search_controls(
            query.query_text,
            size=self.config.max_results_per_source,
            filters=filters if any(key in ["control_type", "applicable_architectures"] for key in filters.keys()) else None
        )
        
        for result in control_results:
            if result["score"] >= self.config.min_semantic_score:
                results["controls"].append({
                    "id": result["id"],
                    "type": "control",
                    "semantic_score": result["score"],
                    "graph_score": 0.0,
                    "data": result["source"]
                })
        
        # Search threats
        threat_results = self.opensearch.semantic_search_threats(
            query.query_text,
            size=self.config.max_results_per_source,
            filters=filters if any(key in ["threat_category", "severity", "applicable_architectures"] for key in filters.keys()) else None
        )
        
        for result in threat_results:
            if result["score"] >= self.config.min_semantic_score:
                results["threats"].append({
                    "id": result["id"],
                    "type": "threat",
                    "semantic_score": result["score"],
                    "graph_score": 0.0,
                    "data": result["source"]
                })
        
        return results
    
    def _perform_graph_search(self, query: HybridSearchQuery) -> Dict[str, List[Dict[str, Any]]]:
        """Perform graph-based search using Neo4j"""
        results = {"controls": [], "threats": [], "relationships": []}
        
        if not query.architecture_type:
            return results
        
        # Find controls for architecture
        arch_controls = self.neo4j.find_controls_for_architecture(query.architecture_type)
        for control in arch_controls:
            graph_score = self._calculate_graph_score_for_control(control, query)
            if graph_score >= self.config.min_graph_score:
                results["controls"].append({
                    "id": control["id"],
                    "type": "control",
                    "semantic_score": 0.0,
                    "graph_score": graph_score,
                    "data": control
                })
        
        # Find threats for architecture
        arch_threats = self.neo4j.find_threats_for_architecture(query.architecture_type)
        for threat in arch_threats:
            graph_score = self._calculate_graph_score_for_threat(threat, query)
            if graph_score >= self.config.min_graph_score:
                results["threats"].append({
                    "id": threat["id"],
                    "type": "threat",
                    "semantic_score": 0.0,
                    "graph_score": graph_score,
                    "data": threat
                })
        
        # Find control gaps (threats without adequate controls)
        if query.include_relationships:
            control_gaps = self.neo4j.find_control_gaps(query.architecture_type)
            for gap in control_gaps:
                threat = gap["threat"]
                graph_score = self._calculate_graph_score_for_threat(threat, query)
                # Boost score for threats with control gaps
                graph_score *= 1.5
                
                if graph_score >= self.config.min_graph_score:
                    results["threats"].append({
                        "id": threat["id"],
                        "type": "threat",
                        "semantic_score": 0.0,
                        "graph_score": graph_score,
                        "data": threat,
                        "control_gap": True,
                        "control_count": gap["control_count"]
                    })
        
        return results
    
    def _calculate_graph_score_for_control(self, control: Dict[str, Any], query: HybridSearchQuery) -> float:
        """Calculate graph-based relevance score for a control"""
        score = 0.5  # Base score
        
        # Boost for effectiveness
        if "effectiveness_rating" in control:
            score += control["effectiveness_rating"] * 0.3
        
        # Boost for matching control types
        if query.control_types and control.get("control_type") in [ct.value for ct in query.control_types]:
            score += 0.2
        
        # Penalize for high cost/complexity
        if "cost_rating" in control:
            score -= control["cost_rating"] * 0.1
        
        if "complexity_rating" in control:
            score -= control["complexity_rating"] * 0.1
        
        return min(1.0, max(0.0, score))
    
    def _calculate_graph_score_for_threat(self, threat: Dict[str, Any], query: HybridSearchQuery) -> float:
        """Calculate graph-based relevance score for a threat"""
        score = 0.5  # Base score
        
        # Boost for high severity
        severity_boost = {
            "critical": 0.4,
            "high": 0.3,
            "medium": 0.2,
            "low": 0.1,
            "info": 0.05
        }
        
        if threat.get("severity") in severity_boost:
            score += severity_boost[threat["severity"]]
        
        # Boost for matching threat categories
        if query.threat_categories and threat.get("threat_category") in [tc.value for tc in query.threat_categories]:
            score += 0.2
        
        # Boost for likelihood and impact
        if "likelihood_score" in threat:
            score += threat["likelihood_score"] * 0.15
        
        if "impact_score" in threat:
            score += threat["impact_score"] * 0.15
        
        return min(1.0, max(0.0, score))
    
    def _combine_results(
        self, 
        semantic_results: Dict[str, List[Dict[str, Any]]], 
        graph_results: Dict[str, List[Dict[str, Any]]],
        semantic_weight: float,
        graph_weight: float
    ) -> List[Dict[str, Any]]:
        """Combine semantic and graph search results"""
        
        combined = {}
        
        # Process semantic results
        for result_type in ["controls", "threats"]:
            for item in semantic_results.get(result_type, []):
                item_id = item["id"]
                if item_id not in combined:
                    combined[item_id] = item.copy()
                else:
                    # Update semantic score if higher
                    if item["semantic_score"] > combined[item_id]["semantic_score"]:
                        combined[item_id]["semantic_score"] = item["semantic_score"]
        
        # Process graph results
        for result_type in ["controls", "threats"]:
            for item in graph_results.get(result_type, []):
                item_id = item["id"]
                if item_id not in combined:
                    combined[item_id] = item.copy()
                else:
                    # Update graph score if higher
                    if item["graph_score"] > combined[item_id]["graph_score"]:
                        combined[item_id]["graph_score"] = item["graph_score"]
                    
                    # Merge additional metadata
                    for key in ["control_gap", "control_count"]:
                        if key in item:
                            combined[item_id][key] = item[key]
        
        # Calculate combined scores
        results = []
        for item_id, item in combined.items():
            combined_score = (
                item["semantic_score"] * semantic_weight + 
                item["graph_score"] * graph_weight
            )
            
            item["combined_score"] = combined_score
            results.append(item)
        
        # Sort by combined score
        results.sort(key=lambda x: x["combined_score"], reverse=True)
        
        return results
    
    def _post_process_results(
        self, 
        results: List[Dict[str, Any]], 
        query: HybridSearchQuery
    ) -> List[SearchResult]:
        """Post-process and format final results"""
        
        final_results = []
        
        for item in results:
            # Get relationships if requested
            relationships = None
            if query.include_relationships:
                relationships = self._get_item_relationships(item["id"], item["type"])
            
            # Create SearchResult
            search_result = SearchResult(
                item_id=item["id"],
                item_type=item["type"],
                name=item["data"].get("name", ""),
                description=item["data"].get("description", ""),
                score=item["combined_score"],
                metadata={
                    "semantic_score": item["semantic_score"],
                    "graph_score": item["graph_score"],
                    "source_data": item["data"],
                    "control_gap": item.get("control_gap", False),
                    "control_count": item.get("control_count", 0)
                },
                relationships=relationships
            )
            
            final_results.append(search_result)
        
        return final_results
    
    def _get_item_relationships(self, item_id: str, item_type: str) -> List[Dict[str, Any]]:
        """Get relationships for an item"""
        relationships = []
        
        try:
            if item_type == "control":
                # Get threats mitigated by this control
                threats = self.neo4j.find_threats_for_control(item_id)
                for threat_rel in threats:
                    relationships.append({
                        "type": "mitigates",
                        "target_id": threat_rel["threat"]["id"],
                        "target_name": threat_rel["threat"]["name"],
                        "effectiveness": threat_rel["relationship"]["effectiveness"],
                        "coverage_percentage": threat_rel["relationship"]["coverage_percentage"]
                    })
            
            elif item_type == "threat":
                # Get controls that mitigate this threat
                controls = self.neo4j.find_controls_for_threat(item_id)
                for control_rel in controls:
                    relationships.append({
                        "type": "mitigated_by",
                        "target_id": control_rel["control"]["id"],
                        "target_name": control_rel["control"]["name"],
                        "effectiveness": control_rel["relationship"]["effectiveness"],
                        "coverage_percentage": control_rel["relationship"]["coverage_percentage"]
                    })
        
        except Exception as e:
            print(f"Error getting relationships for {item_type} {item_id}: {e}")
        
        return relationships
    
    def recommend_controls_for_architecture(self, architecture_type: str, max_results: int = 10) -> List[SearchResult]:
        """Recommend security controls for a specific architecture"""
        
        # Find threats for the architecture
        threats = self.neo4j.find_threats_for_architecture(architecture_type)
        threat_ids = [threat["id"] for threat in threats]
        
        if not threat_ids:
            return []
        
        # Get control recommendations
        recommendations = self.neo4j.recommend_controls_for_threats(threat_ids, architecture_type)
        
        results = []
        for rec in recommendations[:max_results]:
            control = rec["control"]
            
            search_result = SearchResult(
                item_id=control["id"],
                item_type="control",
                name=control["name"],
                description=control["description"],
                score=rec["avg_effectiveness"],
                metadata={
                    "threat_coverage": rec["threat_coverage"],
                    "avg_effectiveness": rec["avg_effectiveness"],
                    "mitigated_threats": rec["mitigated_threats"],
                    "architecture_type": architecture_type,
                    "source_data": control
                }
            )
            
            results.append(search_result)
        
        return results
    
    def analyze_threat_landscape(self, architecture_type: str) -> Dict[str, Any]:
        """Analyze threat landscape for an architecture"""
        
        summary = self.neo4j.get_threat_landscape_summary(architecture_type)
        control_gaps = self.neo4j.find_control_gaps(architecture_type)
        
        # Calculate risk metrics
        high_risk_threats = len([gap for gap in control_gaps if gap["threat"]["severity"] in ["critical", "high"]])
        total_threats = summary.get("total_threats", 0)
        
        risk_score = 0.0
        if total_threats > 0:
            risk_score = (high_risk_threats / total_threats) * 100
        
        return {
            "architecture_type": architecture_type,
            "summary": summary,
            "control_gaps": len(control_gaps),
            "high_risk_threats": high_risk_threats,
            "risk_score": risk_score,
            "recommendations": {
                "priority_gaps": control_gaps[:5],  # Top 5 priority gaps
                "suggested_controls": self.recommend_controls_for_architecture(architecture_type, 5)
            }
        }