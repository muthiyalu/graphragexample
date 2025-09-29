import os
from typing import List, Dict, Any, Optional
from opensearchpy import OpenSearch
from sentence_transformers import SentenceTransformer
import json
from datetime import datetime
import numpy as np

from models.security_models import SecurityControl, ThreatIntelligence


class OpenSearchClient:
    """OpenSearch client for vector-based semantic search"""
    
    def __init__(self):
        # Load environment variables with fallbacks for local demo
        from dotenv import load_dotenv
        load_dotenv()
        
        # Use specific local demo credentials, not global ones
        self.host = os.getenv('DEMO_OPENSEARCH_HOST', 'localhost')
        self.port = int(os.getenv('DEMO_OPENSEARCH_PORT', 9200))
        self.username = os.getenv('DEMO_OPENSEARCH_USERNAME', 'admin')
        self.password = os.getenv('DEMO_OPENSEARCH_PASSWORD', 'StrongPass123@')
        self.use_ssl = os.getenv('DEMO_OPENSEARCH_USE_SSL', 'true').lower() == 'true'
        
        # Initialize OpenSearch client
        self.client = OpenSearch(
            hosts=[{'host': self.host, 'port': self.port}],
            http_auth=(self.username, self.password),
            use_ssl=self.use_ssl,
            verify_certs=False,
            ssl_show_warn=False
        )
        
        # Initialize embedding model
        self.embedding_model = SentenceTransformer(
            os.getenv('EMBEDDING_MODEL', 'all-MiniLM-L6-v2')
        )
        
        # Index names
        self.controls_index = 'security_controls'
        self.threats_index = 'threat_intelligence'
        
        self._create_indices()
    
    def _create_indices(self):
        """Create OpenSearch indices with vector mappings"""
        
        # Security controls index mapping
        controls_mapping = {
            "mappings": {
                "properties": {
                    "id": {"type": "keyword"},
                    "name": {"type": "text", "analyzer": "standard"},
                    "description": {"type": "text", "analyzer": "standard"},
                    "control_type": {"type": "keyword"},
                    "framework": {"type": "keyword"},
                    "control_id": {"type": "keyword"},
                    "implementation_guidance": {"type": "text", "analyzer": "standard"},
                    "effectiveness_rating": {"type": "float"},
                    "cost_rating": {"type": "float"},
                    "complexity_rating": {"type": "float"},
                    "applicable_threats": {"type": "keyword"},
                    "applicable_architectures": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                    "embedding_vector": {
                        "type": "knn_vector",
                        "dimension": 384,  # Dimension for all-MiniLM-L6-v2
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "lucene"
                        }
                    },
                    "combined_text": {"type": "text", "analyzer": "standard"}
                }
            },
            "settings": {
                "index": {
                    "knn": True,
                    "knn.algo_param.ef_search": 100
                }
            }
        }
        
        # Threat intelligence index mapping
        threats_mapping = {
            "mappings": {
                "properties": {
                    "id": {"type": "keyword"},
                    "name": {"type": "text", "analyzer": "standard"},
                    "description": {"type": "text", "analyzer": "standard"},
                    "threat_category": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "attack_vectors": {"type": "keyword"},
                    "affected_components": {"type": "keyword"},
                    "indicators_of_compromise": {"type": "text"},
                    "mitigation_strategies": {"type": "text"},
                    "cve_references": {"type": "keyword"},
                    "mitre_attack_techniques": {"type": "keyword"},
                    "likelihood_score": {"type": "float"},
                    "impact_score": {"type": "float"},
                    "exploitability_score": {"type": "float"},
                    "applicable_architectures": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "first_seen": {"type": "date"},
                    "last_updated": {"type": "date"},
                    "embedding_vector": {
                        "type": "knn_vector",
                        "dimension": 384,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "lucene"
                        }
                    },
                    "combined_text": {"type": "text", "analyzer": "standard"}
                }
            },
            "settings": {
                "index": {
                    "knn": True,
                    "knn.algo_param.ef_search": 100
                }
            }
        }
        
        # Create indices if they don't exist
        if not self.client.indices.exists(index=self.controls_index):
            self.client.indices.create(index=self.controls_index, body=controls_mapping)
            print(f"Created index: {self.controls_index}")
        
        if not self.client.indices.exists(index=self.threats_index):
            self.client.indices.create(index=self.threats_index, body=threats_mapping)
            print(f"Created index: {self.threats_index}")
    
    def _generate_embedding(self, text: str) -> List[float]:
        """Generate embedding vector for text"""
        embedding = self.embedding_model.encode(text)
        return embedding.tolist()
    
    def _prepare_control_document(self, control: SecurityControl) -> Dict[str, Any]:
        """Prepare security control document for indexing"""
        # Combine relevant text fields for embedding
        combined_text = f"{control.name} {control.description} {control.implementation_guidance}"
        
        doc = control.dict()
        doc['embedding_vector'] = self._generate_embedding(combined_text)
        doc['combined_text'] = combined_text
        doc['created_at'] = control.created_at.isoformat()
        doc['updated_at'] = control.updated_at.isoformat()
        
        return doc
    
    def _prepare_threat_document(self, threat: ThreatIntelligence) -> Dict[str, Any]:
        """Prepare threat intelligence document for indexing"""
        # Combine relevant text fields for embedding
        combined_text = f"{threat.name} {threat.description} {' '.join(threat.attack_vectors)} {' '.join(threat.mitigation_strategies)}"
        
        doc = threat.dict()
        doc['embedding_vector'] = self._generate_embedding(combined_text)
        doc['combined_text'] = combined_text
        doc['first_seen'] = threat.first_seen.isoformat()
        doc['last_updated'] = threat.last_updated.isoformat()
        
        return doc
    
    def index_security_control(self, control: SecurityControl) -> bool:
        """Index a security control"""
        try:
            doc = self._prepare_control_document(control)
            response = self.client.index(
                index=self.controls_index,
                id=control.id,
                body=doc
            )
            return response['result'] in ['created', 'updated']
        except Exception as e:
            print(f"Error indexing control {control.id}: {e}")
            return False
    
    def index_threat_intelligence(self, threat: ThreatIntelligence) -> bool:
        """Index threat intelligence"""
        try:
            doc = self._prepare_threat_document(threat)
            response = self.client.index(
                index=self.threats_index,
                id=threat.id,
                body=doc
            )
            return response['result'] in ['created', 'updated']
        except Exception as e:
            print(f"Error indexing threat {threat.id}: {e}")
            return False
    
    def bulk_index_controls(self, controls: List[SecurityControl]) -> Dict[str, int]:
        """Bulk index security controls"""
        actions = []
        for control in controls:
            doc = self._prepare_control_document(control)
            actions.append({
                "_index": self.controls_index,
                "_id": control.id,
                "_source": doc
            })
        
        try:
            response = self.client.bulk(body=actions)
            success_count = sum(1 for item in response['items'] if 'error' not in item.get('index', {}))
            error_count = len(response['items']) - success_count
            return {"success": success_count, "errors": error_count}
        except Exception as e:
            print(f"Error in bulk indexing controls: {e}")
            return {"success": 0, "errors": len(controls)}
    
    def bulk_index_threats(self, threats: List[ThreatIntelligence]) -> Dict[str, int]:
        """Bulk index threat intelligence"""
        actions = []
        for threat in threats:
            doc = self._prepare_threat_document(threat)
            actions.append({
                "_index": self.threats_index,
                "_id": threat.id,
                "_source": doc
            })
        
        try:
            response = self.client.bulk(operations=actions)
            success_count = sum(1 for item in response['items'] if 'error' not in item.get('index', {}))
            error_count = len(response['items']) - success_count
            return {"success": success_count, "errors": error_count}
        except Exception as e:
            print(f"Error in bulk indexing threats: {e}")
            return {"success": 0, "errors": len(threats)}
    
    def semantic_search_controls(
        self, 
        query: str, 
        size: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Perform semantic search on security controls"""
        
        query_vector = self._generate_embedding(query)
        
        search_body = {
            "size": size,
            "query": {
                "bool": {
                    "must": [
                        {
                            "knn": {
                                "embedding_vector": {
                                    "vector": query_vector,
                                    "k": size * 2  # Get more candidates for filtering
                                }
                            }
                        }
                    ]
                }
            },
            "_source": {
                "excludes": ["embedding_vector"]  # Exclude large vector field
            }
        }
        
        # Add filters if provided
        if filters:
            filter_clauses = []
            for field, value in filters.items():
                if isinstance(value, list):
                    filter_clauses.append({"terms": {field: value}})
                else:
                    filter_clauses.append({"term": {field: value}})
            
            if filter_clauses:
                search_body["query"]["bool"]["filter"] = filter_clauses
        
        try:
            response = self.client.search(index=self.controls_index, body=search_body)
            return [
                {
                    "id": hit["_id"],
                    "score": hit["_score"],
                    "source": hit["_source"]
                }
                for hit in response["hits"]["hits"]
            ]
        except Exception as e:
            print(f"Error in semantic search controls: {e}")
            return []
    
    def semantic_search_threats(
        self, 
        query: str, 
        size: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Perform semantic search on threat intelligence"""
        
        query_vector = self._generate_embedding(query)
        
        search_body = {
            "size": size,
            "query": {
                "bool": {
                    "must": [
                        {
                            "knn": {
                                "embedding_vector": {
                                    "vector": query_vector,
                                    "k": size * 2
                                }
                            }
                        }
                    ]
                }
            },
            "_source": {
                "excludes": ["embedding_vector"]
            }
        }
        
        # Add filters if provided
        if filters:
            filter_clauses = []
            for field, value in filters.items():
                if isinstance(value, list):
                    filter_clauses.append({"terms": {field: value}})
                else:
                    filter_clauses.append({"term": {field: value}})
            
            if filter_clauses:
                search_body["query"]["bool"]["filter"] = filter_clauses
        
        try:
            response = self.client.search(index=self.threats_index, body=search_body)
            return [
                {
                    "id": hit["_id"],
                    "score": hit["_score"],
                    "source": hit["_source"]
                }
                for hit in response["hits"]["hits"]
            ]
        except Exception as e:
            print(f"Error in semantic search threats: {e}")
            return []
    
    def get_control_by_id(self, control_id: str) -> Optional[Dict[str, Any]]:
        """Get security control by ID"""
        try:
            response = self.client.get(index=self.controls_index, id=control_id)
            return response["_source"]
        except Exception as e:
            print(f"Error getting control {control_id}: {e}")
            return None
    
    def get_threat_by_id(self, threat_id: str) -> Optional[Dict[str, Any]]:
        """Get threat intelligence by ID"""
        try:
            response = self.client.get(index=self.threats_index, id=threat_id)
            return response["_source"]
        except Exception as e:
            print(f"Error getting threat {threat_id}: {e}")
            return None