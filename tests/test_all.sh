#!/bin/bash

# Master test runner for the entire rollback system
set -e

echo "🧪 Rollback System - Complete Test Suite"
echo "========================================"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test suite
run_test_suite() {
    local name="$1"
    local script="$2"
    local description="$3"
    
    echo -e "\n${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  $name${NC}"
    echo -e "${YELLOW}║  $description${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ -f "$script" ]; then
        if bash "$script"; then
            echo -e "${GREEN}✅ $name: PASSED${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo -e "${RED}❌ $name: FAILED${NC}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        echo -e "${RED}❌ $name: SCRIPT NOT FOUND ($script)${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Print header
echo -e "${BLUE}Project: $PROJECT_ROOT${NC}"
echo -e "${BLUE}Test Directory: $SCRIPT_DIR${NC}"
echo -e "${BLUE}Date: $(date)${NC}"

# Run all test suites
echo -e "\n${BLUE}Starting test execution...${NC}"

# 1. Core librebound unit tests with coverage
echo -e "\n${YELLOW}Running librebound unit tests with coverage...${NC}"
cd "$PROJECT_ROOT/librebound"
mkdir -p ../o
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Run tests with coverage
if go test -cover -coverprofile=${PROJECT_ROOT}/o/coverage.out -v ./...; then
    echo -e "${GREEN}✅ librebound unit tests: PASSED${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    
    # Generate coverage report
    if command -v go >/dev/null && go tool cover -h >/dev/null 2>&1; then
        echo -e "\n${BLUE}📈 Coverage Report:${NC}"
        go tool cover -func=${PROJECT_ROOT}/o/coverage.out | tail -1  # Show total coverage
        echo -e "${BLUE}💡 For detailed coverage: go tool cover -html=${PROJECT_ROOT}/o/coverage.out${NC}"
    fi
else
    echo -e "${RED}❌ librebound unit tests: FAILED${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# 2. End-to-end workflow test
run_test_suite "End-to-End Workflow Test" "$SCRIPT_DIR/test_end_to_end_workflow.sh" "Complete deployment and rollback workflow with all endpoints"

# Build verification
echo -e "\n${YELLOW}Building all components...${NC}"
cd "$PROJECT_ROOT"

# Build all server implementations
for server in "simple-server" "prod-server"; do
    echo -e "\n${BLUE}Building $server...${NC}"
    cd "$PROJECT_ROOT/cmd/$server"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if go build .; then
    echo -e "${GREEN}✅ $server build: PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
    echo -e "${RED}❌ $server build: FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
done

# Print final results
echo -e "\n${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║                    FINAL RESULTS                         ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n📊 Test Summary:"
echo -e "   Total test suites: $TOTAL_TESTS"
echo -e "   ${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "   ${RED}Failed: $FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "\n${GREEN}🎉 ALL TESTS PASSED!${NC}"
    echo -e "${GREEN}   Your rollback system is ready for deployment!${NC}"
    
    echo -e "\n${BLUE}📝 Next Steps:${NC}"
    echo -e "   1. Deploy to TEE environment"
    echo -e "   2. Configure GitHub Actions variables"
    echo -e "   3. Test with real container deployments"
    echo -e "   4. Set up monitoring and alerting"
    
    exit 0
else
    echo -e "\n${RED}💥 SOME TESTS FAILED!${NC}"
    echo -e "${RED}   Please fix the failing tests before deploying.${NC}"
    exit 1
fi
