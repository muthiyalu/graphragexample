#!/usr/bin/env python3
"""
Debug script to check demo OpenSearch connection without interfering with DOADMIN
"""

import os
from dotenv import load_dotenv

# Load our demo environment variables
load_dotenv()

print("🔍 Demo OpenSearch Connection Test")
print("=" * 40)

# Use hardcoded demo values to avoid interfering with your DOADMIN setup
demo_config = {
    'host': 'localhost',
    'port': 9200,
    'username': 'admin',
    'password': 'StrongPass123@',
    'use_ssl': True
}

print(f"Connecting to: {demo_config['host']}:{demo_config['port']}")
print(f"Username: {demo_config['username']}")
print(f"Password: {'*' * len(demo_config['password'])}")
print(f"SSL: {demo_config['use_ssl']}")

print("\n🔧 Testing Demo OpenSearch Connection")
print("-" * 40)

try:
    from opensearchpy import OpenSearch
    
    client = OpenSearch(
        hosts=[{'host': demo_config['host'], 'port': demo_config['port']}],
        http_auth=(demo_config['username'], demo_config['password']),
        use_ssl=demo_config['use_ssl'],
        verify_certs=False,
        ssl_show_warn=False
    )
    
    # Test connection
    info = client.info()
    print(f"✅ Demo OpenSearch connection successful!")
    print(f"OpenSearch version: {info['version']['number']}")
    
    # Test if we can create an index
    test_index = "demo_test_index"
    if client.indices.exists(index=test_index):
        client.indices.delete(index=test_index)
    
    client.indices.create(index=test_index, body={"mappings": {"properties": {"test": {"type": "text"}}}})
    client.indices.delete(index=test_index)
    print("✅ Index creation/deletion test successful!")
    
except Exception as e:
    print(f"❌ Demo connection failed: {e}")
    print(f"Error type: {type(e).__name__}")
    print("\n💡 Your production DOADMIN OpenSearch is preserved and unaffected.")