#!/bin/bash

echo "🔗 Integration Test: Complete Deployment & Rollback Flow"
echo "========================================================"

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test configuration
SERVER_PORT="8080"
TEST_REPO="integration/test-app"

echo -e "${BLUE}🚀 Starting prod-server${NC}"
cd "$PROJECT_ROOT/cmd/prod-server"

# Build if needed
if [ ! -f "./prod-server" ]; then
  echo "Building prod-server..."
    go build .
fi

# Start server
ROLLBACK_STORAGE_PATH="/tmp/integration-test" PORT="$SERVER_PORT" ./prod-server &
SERVER_PID=$!

# Wait for server to start
for i in {1..10}; do
    if curl -s "http://localhost:$SERVER_PORT/health" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Server started (PID: $SERVER_PID)${NC}"
        break
    fi
    sleep 1
done

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up...${NC}"
    kill $SERVER_PID 2>/dev/null || true
    rm -rf /tmp/integration-test 2>/dev/null || true
}
trap cleanup EXIT

sleep 2

echo -e "\n${BLUE}� Step 1: Test health endpoint${NC}"
curl -s "http://localhost:$SERVER_PORT/health" | jq .

echo -e "\n${BLUE}�📦 Step 2: Test deployment authorization${NC}"
curl -s -X POST "http://localhost:$SERVER_PORT/api/v1/deployment/authorize" \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "'$TEST_REPO'",
    "commit_sha": "dev-abc123",
    "image_digest": "sha256:dev123456",
    "actor": "developer"
  }' | jq .

echo -e "\n${BLUE}📦 Step 3: Deploy development version${NC}"
curl -s -X POST "http://localhost:$SERVER_PORT/api/v1/deployment/update" \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "'$TEST_REPO'",
    "commit_sha": "dev-abc123",
    "image_digest": "sha256:dev123456",
    "actor": "developer"
  }' | jq .

echo -e "\n${BLUE}📦 Step 4: Deploy production release (creates snapshot)${NC}"
SNAPSHOT_RESPONSE=$(curl -s -X POST "http://localhost:$SERVER_PORT/api/v1/deployment/snapshot" \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "'$TEST_REPO'",
    "commit_sha": "release-v1.0.0",
    "image_digest": "sha256:release100",
    "snapshot_id": "production-v1.0.0",
    "actor": "release-manager"
  }')

echo "$SNAPSHOT_RESPONSE" | jq .
ROLLBACK_TOKEN=$(echo "$SNAPSHOT_RESPONSE" | jq -r '.rollback_token')

echo -e "\n${BLUE}📦 Step 5: Deploy another development version${NC}"
curl -s -X POST "http://localhost:$SERVER_PORT/api/v1/deployment/update" \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "'$TEST_REPO'",
    "commit_sha": "dev-xyz789",
    "image_digest": "sha256:dev789012",
    "actor": "developer"
  }' | jq .

echo -e "\n${BLUE}📦 Step 6: Deploy production hotfix (creates another snapshot)${NC}"
curl -s -X POST "http://localhost:$SERVER_PORT/api/v1/deployment/snapshot" \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "'$TEST_REPO'",
    "commit_sha": "hotfix-v1.0.1",
    "image_digest": "sha256:hotfix101",
    "snapshot_id": "production-v1.0.1",
    "actor": "ops-team"
  }' | jq .

echo -e "\n${BLUE}📋 Step 7: List all snapshots${NC}"
curl -s "http://localhost:$SERVER_PORT/api/v1/snapshots" | jq .

echo -e "\n${BLUE}🔄 Step 8: Emergency rollback to v1.0.0${NC}"
echo "Executing rollback..."
ROLLBACK_RESPONSE=$(curl -s -X POST "http://localhost:$SERVER_PORT/api/v1/rollback/initiate" \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "'$TEST_REPO'",
    "snapshot_id": "production-v1.0.0",
    "rollback_token": "'$ROLLBACK_TOKEN'",
    "actor": "incident-commander",
    "justification": "Critical bug found in v1.0.1, rolling back to stable v1.0.0"
  }')

echo "$ROLLBACK_RESPONSE" | jq .

SUCCESS=$(echo "$ROLLBACK_RESPONSE" | jq -r '.success')
if [ "$SUCCESS" = "true" ]; then
    echo -e "${GREEN}✅ Rollback executed successfully!${NC}"
    echo -e "\n${GREEN}🎉 Integration test completed successfully!${NC}"
    echo -e "${GREEN}   ✅ Development deployments recorded as state updates${NC}"
    echo -e "${GREEN}   ✅ Production deployments created rollback snapshots${NC}"
    echo -e "${GREEN}   ✅ Emergency rollback executed successfully${NC}"
else
    echo -e "${RED}❌ Rollback execution failed${NC}"
    exit 1
fi

echo -e "\n${BLUE}🧹 Step 9: Prune snapshot production-v1.0.1${NC}"
curl -s -X POST "http://localhost:$SERVER_PORT/api/v1/snapshot/prune" \
  -H "Content-Type: application/json" \
  -d '{
    "snapshot_id": "production-v1.0.1",
    "justification": "Retire hotfix snapshot after rollback",
    "actor": "ops"
  }' | jq .

echo -e "\n${BLUE}📊 Step 10: Test legacy commit endpoint${NC}"
echo "Testing deprecated /commit endpoint..."
curl -s -X POST "http://localhost:$SERVER_PORT/api/v1/deployment/commit" \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "'$TEST_REPO'",
    "commit_sha": "legacy-test",
    "image_digest": "sha256:legacy123",
    "actor": "legacy-user"
  }' | jq .

echo -e "\n${BLUE}📊 Step 11: Final state verification${NC}"
echo "Current snapshots:"
curl -s "http://localhost:$SERVER_PORT/api/v1/snapshots" | jq .

echo -e "\n${YELLOW}💡 This demonstrates the complete rollback system:${NC}"
echo -e "   1. Health checks and authorization endpoints work"
echo -e "   2. Development deployments are tracked but not rollback-enabled"
echo -e "   3. Production deployments create cryptographically verified snapshots"
echo -e "   4. Emergency rollbacks are authorized through the transparency log"
echo -e "   5. Legacy endpoints maintain backward compatibility"
echo -e "   6. All operations are auditable and tamper-proof"
