#!/usr/bin/env python3
"""
Test script to check OpenSearch and Neo4j connectivity without the full application
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_opensearch():
    """Test OpenSearch connectivity"""
    try:
        from opensearchpy import OpenSearch
        from dotenv import load_dotenv
        import os
        
        # Load our demo environment variables
        load_dotenv()
        
        client = OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            http_auth=('admin', 'StrongPass123@'),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )
        
        # Test connection
        info = client.info()
        print("✅ OpenSearch connected successfully!")
        print(f"   Version: {info['version']['number']}")
        return True
        
    except Exception as e:
        print(f"❌ OpenSearch connection failed: {e}")
        print("💡 Make sure OpenSearch is running on localhost:9200")
        return False

def test_neo4j():
    """Test Neo4j connectivity"""
    try:
        from neo4j import GraphDatabase
        
        driver = GraphDatabase.driver(
            "bolt://localhost:7687",
            auth=("neo4j", "password")
        )
        
        # Test connection
        with driver.session() as session:
            result = session.run("RETURN 1 as test")
            record = result.single()
            
        driver.close()
        print("✅ Neo4j connected successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Neo4j connection failed: {e}")
        print("💡 Make sure Neo4j is running on localhost:7474")
        return False

def test_imports():
    """Test that all required packages can be imported"""
    try:
        import opensearchpy
        import neo4j
        import sentence_transformers
        import pydantic
        print("✅ All packages imported successfully!")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

if __name__ == "__main__":
    print("🔧 Testing Security Hybrid Search Prerequisites")
    print("=" * 50)
    
    print("\n1. Testing package imports...")
    imports_ok = test_imports()
    
    print("\n2. Testing OpenSearch connection...")
    opensearch_ok = test_opensearch()
    
    print("\n3. Testing Neo4j connection...")
    neo4j_ok = test_neo4j()
    
    print("\n" + "=" * 50)
    
    if imports_ok and opensearch_ok and neo4j_ok:
        print("🎉 All tests passed! Ready to run the main application.")
    else:
        print("⚠️  Some tests failed. Please check the prerequisites:")
        if not opensearch_ok:
            print("   - Start OpenSearch: docker run -d -p 9200:9200 -e 'discovery.type=single-node' opensearchproject/opensearch:latest")
        if not neo4j_ok:
            print("   - Start Neo4j: docker run -d -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password neo4j:latest")