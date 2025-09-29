# Security Controls & Threat Intelligence Hybrid Search System

This project demonstrates how to combine OpenSearch (vector database) with Neo4j (graph database) to create a hybrid search system for security controls and threat intelligence data.

## Architecture

- **OpenSearch**: Vector database for semantic similarity search of security controls and threats
- **Neo4j**: Graph database for relationship-based queries and threat modeling
- **Hybrid Search**: Combines vector and graph search for comprehensive threat analysis

## Use Cases

1. **Web Application Threat Analysis**: Analyze threats for standard architectures like web applications
2. **Security Controls Recommendations**: Provide relevant controls based on threats and architecture

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Start OpenSearch and Neo4j locally (using Docker):
```bash
# OpenSearch
docker run -d -p 9200:9200 -p 9600:9600 \
  -e "discovery.type=single-node" \
  -e "OPENSEARCH_INITIAL_ADMIN_PASSWORD=admin" \
  opensearchproject/opensearch:latest

# Neo4j
docker run -d -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:latest
```

3. Configure environment variables in `.env`

4. Run the example:
```bash
python main.py
```

## Project Structure

- `models/`: Data models for security controls, threats, and relationships
- `database/`: Database clients and connection management
- `services/`: Business logic for hybrid search functionality
- `examples/`: Use case implementations
- `data/`: Sample security controls and threat intelligence data