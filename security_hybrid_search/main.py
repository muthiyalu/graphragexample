"""
Main application demonstrating the hybrid security search system
"""

import os
import sys
from dotenv import load_dotenv
import asyncio
import json

# Load environment variables
load_dotenv()

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database.opensearch_client import OpenSearchClient
from database.neo4j_client import Neo4jClient
from services.hybrid_search import HybridSearchEngine
from examples.web_app_analysis import WebAppSecurityAnalyzer
from examples.api_analysis import APISecurityAnalyzer
from data.sample_data import (
    generate_sample_security_controls,
    generate_sample_threat_intelligence,
    generate_sample_architectures,
    generate_sample_relationships
)
from models.security_models import HybridSearchQuery, ThreatCategory, ControlType


class SecurityHybridSearchDemo:
    """Main demonstration class for the hybrid search system"""
    
    def __init__(self):
        print("🚀 Initializing Security Hybrid Search System")
        print("=" * 60)
        
        try:
            # Initialize database clients
            self.opensearch_client = OpenSearchClient()
            self.neo4j_client = Neo4jClient()
            
            # Initialize hybrid search engine
            self.hybrid_search = HybridSearchEngine(
                self.opensearch_client, 
                self.neo4j_client
            )
            
            print("✅ Database connections established")
            
        except Exception as e:
            print(f"❌ Failed to initialize system: {e}")
            print("\n💡 Make sure OpenSearch and Neo4j are running:")
            print("   - OpenSearch: http://localhost:9200")
            print("   - Neo4j: http://localhost:7474")
            sys.exit(1)
    
    def load_sample_data(self):
        """Load sample security data into the system"""
        
        print("\n📊 Loading Sample Data...")
        print("-" * 30)
        
        try:
            # Generate sample data
            controls = generate_sample_security_controls()
            threats = generate_sample_threat_intelligence()
            architectures = generate_sample_architectures()
            relationships = generate_sample_relationships()
            
            # Load data into OpenSearch
            print("Loading controls into OpenSearch...")
            control_result = self.opensearch_client.bulk_index_controls(controls)
            print(f"   ✅ {control_result['success']} controls indexed, {control_result['errors']} errors")
            
            print("Loading threats into OpenSearch...")
            threat_result = self.opensearch_client.bulk_index_threats(threats)
            print(f"   ✅ {threat_result['success']} threats indexed, {threat_result['errors']} errors")
            
            # Load data into Neo4j
            print("Loading data into Neo4j...")
            
            # Load controls
            for control in controls:
                self.neo4j_client.create_security_control_node(control)
            
            # Load threats
            for threat in threats:
                self.neo4j_client.create_threat_intelligence_node(threat)
            
            # Load architectures
            for arch in architectures:
                self.neo4j_client.create_architecture_node(arch)
            
            # Create relationships
            for rel in relationships:
                self.neo4j_client.create_threat_control_relationship(
                    rel.threat_id, rel.control_id, rel
                )
            
            print(f"   ✅ {len(controls)} controls, {len(threats)} threats, {len(architectures)} architectures")
            print(f"   ✅ {len(relationships)} relationships created")
            
        except Exception as e:
            print(f"❌ Error loading sample data: {e}")
    
    def demonstrate_hybrid_search(self):
        """Demonstrate hybrid search capabilities"""
        
        print("\n🔍 Hybrid Search Demonstration")
        print("-" * 35)
        
        # Example 1: Web application security query
        print("\n1. Web Application Security Analysis")
        print("   Query: 'web application injection authentication'")
        
        query1 = HybridSearchQuery(
            query_text="web application injection authentication",
            architecture_type="web_app",
            threat_categories=[ThreatCategory.INJECTION, ThreatCategory.BROKEN_AUTH],
            max_results=5,
            semantic_weight=0.7,
            graph_weight=0.3
        )
        
        results1 = self.hybrid_search.search(query1)
        
        print(f"   📊 Found {len(results1)} results:")
        for i, result in enumerate(results1[:3], 1):
            print(f"      {i}. {result.name} ({result.item_type})")
            print(f"         Score: {result.score:.3f} | Semantic: {result.metadata['semantic_score']:.3f} | Graph: {result.metadata['graph_score']:.3f}")
        
        # Example 2: API security query
        print("\n2. API Security Analysis")
        print("   Query: 'API rate limiting authentication authorization'")
        
        query2 = HybridSearchQuery(
            query_text="API rate limiting authentication authorization",
            architecture_type="api",
            control_types=[ControlType.PREVENTIVE],
            max_results=5
        )
        
        results2 = self.hybrid_search.search(query2)
        
        print(f"   📊 Found {len(results2)} results:")
        for i, result in enumerate(results2[:3], 1):
            print(f"      {i}. {result.name} ({result.item_type})")
            print(f"         Score: {result.score:.3f}")
    
    def demonstrate_threat_analysis(self):
        """Demonstrate threat landscape analysis"""
        
        print("\n🛡️ Threat Landscape Analysis")
        print("-" * 35)
        
        # Analyze web application threat landscape
        landscape = self.hybrid_search.analyze_threat_landscape("web_app")
        
        print("Web Application Threat Landscape:")
        print(f"   Total Threats: {landscape.get('summary', {}).get('total_threats', 0)}")
        print(f"   Total Controls: {landscape.get('summary', {}).get('total_controls', 0)}")
        print(f"   Control Gaps: {landscape.get('control_gaps', 0)}")
        print(f"   Risk Score: {landscape.get('risk_score', 0):.1f}%")
        
        # Show control recommendations
        recommendations = landscape.get('recommendations', {}).get('suggested_controls', [])
        if recommendations:
            print("\n   Top Control Recommendations:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"      {i}. {rec.name}")
                print(f"         Effectiveness: {rec.score:.3f}")
                print(f"         Threat Coverage: {rec.metadata.get('threat_coverage', 0)}")
    
    def demonstrate_specialized_analysis(self):
        """Demonstrate specialized security analysis"""
        
        print("\n🎯 Specialized Security Analysis")
        print("-" * 40)
        
        # Web application analysis
        web_analyzer = WebAppSecurityAnalyzer(self.hybrid_search)
        
        print("1. OWASP Top 10 Analysis")
        try:
            owasp_analysis = web_analyzer.get_owasp_top10_analysis()
            categories_analyzed = len(owasp_analysis.get('categories', []))
            print(f"   ✅ Analyzed {categories_analyzed} OWASP categories")
            
            # Show one example category
            if owasp_analysis.get('categories'):
                example_cat = owasp_analysis['categories'][0]
                print(f"   Example - {example_cat['category']}:")
                print(f"      Threats found: {example_cat['threat_count']}")
                print(f"      Average score: {example_cat['avg_score']:.3f}")
        
        except Exception as e:
            print(f"   ⚠️ Analysis requires more sample data: {e}")
        
        print("\n2. Security Gap Analysis")
        try:
            gap_analysis = web_analyzer.identify_security_gaps()
            print(f"   ✅ Identified {gap_analysis.get('summary', {}).get('total_gaps', 0)} control gaps")
            print(f"   Risk Score: {gap_analysis.get('summary', {}).get('risk_score', 0):.1f}%")
        
        except Exception as e:
            print(f"   ⚠️ Gap analysis requires more sample data: {e}")
    
    def interactive_demo(self):
        """Interactive demonstration mode"""
        
        print("\n🎮 Interactive Demo Mode")
        print("-" * 25)
        print("Enter queries to search for security controls and threats")
        print("Examples:")
        print("  - 'SQL injection prevention'")
        print("  - 'microservices authentication'")
        print("  - 'API rate limiting'")
        print("Type 'quit' to exit\n")
        
        while True:
            try:
                user_query = input("🔍 Enter search query: ").strip()
                
                if user_query.lower() in ['quit', 'exit', 'q']:
                    break
                
                if not user_query:
                    continue
                
                # Create hybrid search query
                query = HybridSearchQuery(
                    query_text=user_query,
                    max_results=5,
                    include_relationships=True
                )
                
                # Perform search
                results = self.hybrid_search.search(query)
                
                print(f"\n📊 Found {len(results)} results:")
                for i, result in enumerate(results, 1):
                    print(f"\n{i}. {result.name} ({result.item_type.upper()})")
                    print(f"   Score: {result.score:.3f}")
                    print(f"   Description: {result.description[:100]}...")
                    
                    if result.relationships:
                        print(f"   Relationships: {len(result.relationships)} connections")
                
                print("\n" + "-" * 50)
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
        
        print("\n👋 Thanks for using the Security Hybrid Search Demo!")
    
    def run_demo(self):
        """Run the complete demonstration"""
        
        try:
            # Load sample data
            self.load_sample_data()
            
            # Run demonstrations
            self.demonstrate_hybrid_search()
            self.demonstrate_threat_analysis()
            self.demonstrate_specialized_analysis()
            
            # Ask user if they want interactive mode
            print("\n" + "=" * 60)
            choice = input("Would you like to try interactive search? (y/n): ").strip().lower()
            
            if choice in ['y', 'yes']:
                self.interactive_demo()
            
            print("\n✅ Demo completed successfully!")
            
        except Exception as e:
            print(f"❌ Demo failed: {e}")
        
        finally:
            # Cleanup
            self.neo4j_client.close()
            print("🔧 Database connections closed")


def main():
    """Main function"""
    
    print("🔐 Security Hybrid Search System")
    print("Combining OpenSearch (Vector DB) + Neo4j (Graph DB)")
    print("For Security Controls & Threat Intelligence Analysis")
    print("=" * 60)
    
    # Check if databases are available
    print("\n🔧 Prerequisites Check:")
    print("1. OpenSearch should be running on localhost:9200")
    print("2. Neo4j should be running on localhost:7474")
    print("3. Install dependencies: pip install -r requirements.txt")
    
    proceed = input("\nProceed with demo? (y/n): ").strip().lower()
    
    if proceed in ['y', 'yes']:
        demo = SecurityHybridSearchDemo()
        demo.run_demo()
    else:
        print("Demo cancelled. Setup the prerequisites and try again!")


if __name__ == "__main__":
    main()