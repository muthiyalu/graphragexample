#!/bin/bash
# Quick Setup Script for Security Hybrid Search Demo
# Run this script to set up the complete environment

echo "🚀 Security Hybrid Search System Setup"
echo "======================================"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop first."
    exit 1
fi

echo "✅ Docker is running"

# Stop and remove any existing containers
echo "🧹 Cleaning up existing containers..."
docker stop opensearch neo4j 2>/dev/null || true
docker rm opensearch neo4j 2>/dev/null || true

# Start OpenSearch
echo "🔍 Starting OpenSearch..."
docker run -d -p 9200:9200 -p 9600:9600 \
  -e "discovery.type=single-node" \
  -e "OPENSEARCH_INITIAL_ADMIN_PASSWORD=StrongPass123@" \
  --name opensearch opensearchproject/opensearch:latest

# Start Neo4j
echo "📊 Starting Neo4j..."
docker run -d -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  --name neo4j neo4j:latest

echo "⏳ Waiting for services to start..."
sleep 30

# Check if containers are running
echo "🔧 Checking container status..."
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "✅ Setup complete!"
echo ""
echo "🔍 OpenSearch: https://localhost:9200 (admin:StrongPass123@)"
echo "📊 Neo4j Browser: http://localhost:7474 (neo4j:password)"
echo ""
echo "Next steps:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Test setup: python test_setup.py"
echo "3. Run demo: python main.py"