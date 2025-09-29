# Troubleshooting Guide

## Quick Diagnostics

### 1. Check Docker Containers
```bash
# See all running containers
docker ps

# See all containers (including stopped)
docker ps -a

# Expected output should show:
# - opensearch (running, ports 9200:9200, 9600:9600)
# - neo4j (running, ports 7474:7474, 7687:7687)
```

### 2. Test Database Connections
```bash
# Test OpenSearch
curl -k -u admin:StrongPass123@ https://localhost:9200/_cluster/health

# Test Neo4j (should return connection info)
echo "RETURN 1" | docker exec -i neo4j cypher-shell -u neo4j -p password
```

### 3. Run Built-in Tests
```bash
# Comprehensive connection test
python test_setup.py

# Debug environment variables
python debug_env.py
```

## Common Issues & Solutions

### OpenSearch Issues

#### Issue: "Connection refused"
**Cause**: OpenSearch not started or still starting up
**Solution**:
```bash
# Check if container is running
docker ps | grep opensearch

# If not running, start it
docker run -d -p 9200:9200 -p 9600:9600 \
  -e "discovery.type=single-node" \
  -e "OPENSEARCH_INITIAL_ADMIN_PASSWORD=StrongPass123@" \
  --name opensearch opensearchproject/opensearch:latest

# Wait longer for startup (can take 60+ seconds)
sleep 60
python test_setup.py
```

#### Issue: "Authentication failed"
**Cause**: Wrong password or SSL settings
**Solution**:
```bash
# Verify password works with curl
curl -k -u admin:StrongPass123@ https://localhost:9200/_cluster/health

# If curl works but Python doesn't, check .env file has:
# DEMO_OPENSEARCH_PASSWORD=StrongPass123@
# DEMO_OPENSEARCH_USE_SSL=true
```

#### Issue: "Password validation failed"
**Cause**: OpenSearch requires strong passwords
**Current Password**: `StrongPass123@` (meets all requirements)
- 8+ characters ✅
- Uppercase letter ✅
- Lowercase letter ✅
- Digit ✅
- Special character ✅

#### Issue: Container exits immediately
**Solution**:
```bash
# Check logs for detailed error
docker logs opensearch

# Common fix: remove old containers
docker rm opensearch
# Then restart with correct command
```

### Neo4j Issues

#### Issue: "Connection failed to bolt://localhost:7687"
**Solution**:
```bash
# Check if Neo4j is running
docker ps | grep neo4j

# If not running
docker run -d -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  --name neo4j neo4j:latest

# Wait for startup
sleep 15
python test_setup.py
```

#### Issue: "Authentication failed"
**Credentials**: neo4j:password (as configured)

### Python/Environment Issues

#### Issue: "Module not found"
**Solution**:
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # You should see (venv) in prompt

# Reinstall dependencies
pip install -r requirements.txt
```

#### Issue: "Command not found: python"
**Solution**:
```bash
# Try python3 instead
python3 test_setup.py

# Or check Python installation
which python
which python3
```

### Environment Variable Issues

#### Issue: Wrong OpenSearch credentials being used
**Cause**: System has other OpenSearch environment variables
**Solution**: This demo uses `DEMO_OPENSEARCH_*` variables to avoid conflicts
- No action needed - system designed to work alongside production OpenSearch

### Port Conflicts

#### Issue: "Port already in use"
**Solution**:
```bash
# Check what's using the ports
lsof -i :9200
lsof -i :7474
lsof -i :7687

# Stop conflicting services or use different ports
docker run -d -p 9201:9200 -p 9601:9600 ...
# (then update .env file accordingly)
```

## Reset Everything (Nuclear Option)

If nothing works, start fresh:

```bash
# 1. Stop and remove all containers
docker stop opensearch neo4j
docker rm opensearch neo4j

# 2. Remove Python environment
deactivate  # if in virtual env
rm -rf venv

# 3. Start fresh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Run setup script
./setup.sh

# 5. Test
python test_setup.py
```

## Getting Help

### Check System Resources
```bash
# Ensure Docker has enough memory (4GB+ recommended)
docker system info | grep -i memory

# Check disk space
df -h
```

### Useful Commands
```bash
# View real-time logs
docker logs -f opensearch
docker logs -f neo4j

# Enter container for debugging
docker exec -it opensearch bash
docker exec -it neo4j bash

# Check container resource usage
docker stats
```

### Environment Details
- **OpenSearch Version**: 3.2.0
- **Neo4j Version**: Latest (5.x)
- **Python Requirements**: See requirements.txt
- **OS Compatibility**: macOS, Linux, Windows (with WSL2)

If issues persist, check:
1. Docker Desktop is running and has sufficient resources
2. No firewall blocking ports 9200, 7474, 7687
3. No other services using these ports
4. Virtual environment is properly activated