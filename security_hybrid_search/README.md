# Security Controls & Threat Intelligence Hybrid Search System

This project demonstrates how to combine OpenSearch (vector database) with Neo4j (graph database) to create a hybrid search system for security controls and threat intelligence data.

## Architecture

- **OpenSearch**: Vector database for semantic similarity search of security controls and threats
- **Neo4j**: Graph database for relationship-based queries and threat modeling
- **Hybrid Search**: Combines vector and graph search for comprehensive threat analysis

## Use Cases

1. **Web Application Threat Analysis**: Analyze threats for standard architectures like web applications
2. **Security Controls Recommendations**: Provide relevant controls based on threats and architecture
3. **OWASP Top 10 Analysis**: Comprehensive analysis across all OWASP threat categories
4. **Security Gap Analysis**: Identify threats without adequate controls
5. **Framework-based Recommendations**: Controls from NIST, ISO27001, CIS, OWASP frameworks

## 🚀 Complete Installation Guide

### Prerequisites

- Docker Desktop installed and running
- Python 3.8+ installed
- Git (for cloning the repository)

### Step 1: Clone and Setup Project

```bash
# Clone the repository
git clone <your-repo-url>
cd graphragexample/security_hybrid_search

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### Step 2: Start Database Services

#### Start OpenSearch (Vector Database)
```bash
docker run -d -p 9200:9200 -p 9600:9600 \
  -e "discovery.type=single-node" \
  -e "OPENSEARCH_INITIAL_ADMIN_PASSWORD=StrongPass123@" \
  --name opensearch opensearchproject/opensearch:latest
```

#### Start Neo4j (Graph Database)
```bash
docker run -d -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  --name neo4j neo4j:latest
```

### Step 3: Verify Database Connections

```bash
# Test OpenSearch (should return cluster health)
curl -k -u admin:StrongPass123@ https://localhost:9200/_cluster/health

# Test Neo4j (open in browser)
# Navigate to: http://localhost:7474
# Login: neo4j / password
```

### Step 4: Configure Environment Variables

The `.env` file is already configured with the correct settings:

```bash
# Demo OpenSearch Configuration (separate from production)
DEMO_OPENSEARCH_HOST=localhost
DEMO_OPENSEARCH_PORT=9200
DEMO_OPENSEARCH_USERNAME=admin
DEMO_OPENSEARCH_PASSWORD=StrongPass123@
DEMO_OPENSEARCH_USE_SSL=true

# Neo4j Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=password

# Embedding Model
EMBEDDING_MODEL=all-MiniLM-L6-v2
```

### Step 5: Test the Setup

```bash
# Run the connection test
python test_setup.py
```

You should see:
```
✅ All packages imported successfully!
✅ OpenSearch connected successfully!
✅ Neo4j connected successfully!
🎉 All tests passed! Ready to run the main application.
```

### Step 6: Run the Demo

```bash
# Start the hybrid search demo
python main.py
```

Follow the interactive prompts to:
1. Load sample security data
2. Perform hybrid searches
3. Analyze threat landscapes
4. Try interactive search queries

## 🐛 Troubleshooting

### OpenSearch Issues

**Problem**: OpenSearch container fails to start
```bash
# Check container logs
docker logs opensearch

# Common fix: Remove old containers and restart
docker rm opensearch
docker run -d -p 9200:9200 -p 9600:9600 \
  -e "discovery.type=single-node" \
  -e "OPENSEARCH_INITIAL_ADMIN_PASSWORD=StrongPass123@" \
  --name opensearch opensearchproject/opensearch:latest
```

**Problem**: Connection refused to OpenSearch
```bash
# Wait for OpenSearch to fully start (can take 30-60 seconds)
sleep 30
python test_setup.py

# Check if running on correct port
docker ps
```

### Neo4j Issues

**Problem**: Neo4j connection failed
```bash
# Check if Neo4j is running
docker ps | grep neo4j

# Restart Neo4j if needed
docker restart neo4j

# Wait for startup
sleep 10
python test_setup.py
```

### Environment Variable Issues

**Problem**: Using wrong OpenSearch credentials
- This demo uses `DEMO_OPENSEARCH_*` variables to avoid conflicts with production OpenSearch setups
- If you have existing OpenSearch environment variables, they won't interfere

## 🔧 Docker Management Commands

### Check Running Containers
```bash
docker ps
```

### Stop Services
```bash
docker stop opensearch neo4j
```

### Start Existing Services
```bash
docker start opensearch neo4j
```

### Remove Services (Clean Slate)
```bash
docker rm -f opensearch neo4j
```

### View Logs
```bash
# OpenSearch logs
docker logs opensearch

# Neo4j logs
docker logs neo4j
```

## 🎯 Example Queries

Once the system is running, try these interactive queries:

- `"SQL injection prevention"`
- `"web application authentication"`
- `"API rate limiting controls"`
- `"microservices security"`
- `"OWASP top 10 threats"`

## 📁 Project Structure

```
security_hybrid_search/
├── models/           # Data models for security entities
├── database/         # OpenSearch and Neo4j clients
├── services/         # Hybrid search engine
├── examples/         # Use case implementations
├── data/             # Sample security data
├── main.py           # Main demo application
├── test_setup.py     # Connection testing
├── debug_env.py      # Environment debugging
├── requirements.txt  # Python dependencies
├── .env             # Environment configuration
└── README.md        # This file
```

## 🚨 Important Notes

1. **Demo vs Production**: This uses demo-specific environment variables (`DEMO_OPENSEARCH_*`) to avoid interfering with any existing OpenSearch production setups.

2. **Security**: The passwords used here are for demo purposes only. Use strong, unique passwords in production.

3. **Data Persistence**: Docker containers use ephemeral storage. Data will be lost when containers are removed. For production, use proper volume mounts.

4. **Memory**: Ensure Docker has at least 4GB RAM allocated for optimal performance.

## 🔍 What This Demo Shows

- **Vector Search**: Semantic similarity using sentence transformers
- **Graph Relationships**: Complex threat-control mappings
- **Hybrid Scoring**: Weighted combination of semantic + graph relevance
- **Security Analysis**: OWASP Top 10, gap analysis, framework recommendations
- **Interactive Search**: Real-time query capabilities

This system demonstrates the power of combining vector databases (for semantic understanding) with graph databases (for relationship modeling) in the security domain.