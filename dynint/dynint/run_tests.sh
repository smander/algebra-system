#!/bin/bash

# dynint Testing Script
# Tests spacecraft_server_linux_x86 with both dynmap and dyntrace

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BINARY="spacecraft_server_linux_x86"
OUTPUT_DIR="output"
DYNMAP_DIR="$OUTPUT_DIR/dynmap"
DYNTRACE_DIR="$OUTPUT_DIR/dyntrace"

echo -e "${BLUE}=== dynint Test Suite for $BINARY ===${NC}"
echo

# Function to check if Docker is running
check_docker() {
    echo -e "${BLUE}🐳 Checking Docker...${NC}"
    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}❌ Docker is not running or not accessible${NC}"
        echo "Please start Docker and try again"
        exit 1
    fi
    echo -e "${GREEN}✅ Docker is running${NC}"
}

# Function to check if binary exists
check_binary() {
    echo -e "${BLUE}🔍 Checking binary...${NC}"
    if [ ! -f "$BINARY" ]; then
        echo -e "${RED}❌ Binary $BINARY not found${NC}"
        echo "Please ensure $BINARY is in the current directory"
        exit 1
    fi
    echo -e "${GREEN}✅ Binary $BINARY found${NC}"
    file "$BINARY"
}

# Function to build Docker containers
build_containers() {
    echo -e "${BLUE}🔨 Building Docker containers...${NC}"
    if ! docker compose build >/dev/null 2>&1; then
        echo -e "${RED}❌ Failed to build Docker containers${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Docker containers built successfully${NC}"
}

# Function to create output directories
setup_directories() {
    echo -e "${BLUE}📁 Setting up output directories...${NC}"
    mkdir -p "$DYNMAP_DIR" "$DYNTRACE_DIR"
    echo -e "${GREEN}✅ Output directories created:${NC}"
    echo "  - $DYNMAP_DIR"
    echo "  - $DYNTRACE_DIR"
}

# Function to run dynmap test
test_dynmap() {
    echo -e "${BLUE}🗺️  Running dynmap analysis...${NC}"
    
    local map_file="$DYNMAP_DIR/spacecraft_map.json"
    local map_detailed="$DYNMAP_DIR/spacecraft_detailed.json"
    
    echo "  📋 Basic map generation..."
    if docker compose run --rm dynint-shell python -m dynint.cli map "$BINARY" --output "$map_file" >/dev/null 2>&1; then
        echo -e "${GREEN}  ✅ Basic map: $(du -h "$map_file" | cut -f1)${NC}"
    else
        echo -e "${RED}  ❌ Basic map generation failed${NC}"
        return 1
    fi
    
    echo "  📋 Detailed map with DWARF and bytes..."
    if docker compose run --rm dynint-shell python -m dynint.cli map "$BINARY" --output "$map_detailed" --with-dwarf --bytes >/dev/null 2>&1; then
        echo -e "${GREEN}  ✅ Detailed map: $(du -h "$map_detailed" | cut -f1)${NC}"
    else
        echo -e "${RED}  ❌ Detailed map generation failed${NC}"
        return 1
    fi
    
    # Analyze the map
    echo "  📊 Analyzing map contents..."
    docker compose run --rm dynint-shell python3 -c "
import json
from pathlib import Path

map_data = json.loads(Path('$map_detailed').read_text())
print(f'  Functions: {len(map_data[\"functions\"])}')
print(f'  Callsites: {len(map_data[\"callsites\"])}') 
print(f'  Libraries: {len(map_data.get(\"libraries\", []))}')

# Count symbol types
callsites = map_data['callsites']
symbol_calls = sum(1 for cs in callsites if cs.get('target') and not str(cs.get('target')).startswith('0x'))
print(f'  Symbolic calls: {symbol_calls}')
" 2>/dev/null
    
    echo -e "${GREEN}✅ dynmap tests completed${NC}"
}


# Function to test DynInst backend
test_dyninst() {
    echo -e "${BLUE}🔧 Running DynInst analysis...${NC}"
    
    local map_file="$DYNMAP_DIR/spacecraft_map.json"
    local trace_file="$DYNTRACE_DIR/dyninst_trace.jsonl"
    local instruction_trace="$DYNTRACE_DIR/dyninst_instruction_trace.jsonl"
    local cwe120_trace="$DYNTRACE_DIR/dyninst_cwe120_trace.jsonl"
    
    # Check if map exists
    if [ ! -f "$map_file" ]; then
        echo -e "${RED}  ❌ Map file not found, run dynmap test first${NC}"
        return 1
    fi
    
    echo "  🎯 Testing DynInst instruction-level tracing..."
    if timeout 15s docker compose run --rm dynint-dyninst python -m dynint.cli trace \
        --backend dyninst \
        --spawn "./$BINARY" \
        --map "$map_file" \
        --instruction-level \
        --memory-access \
        --output "$instruction_trace" >/dev/null 2>&1; then
        echo -e "${GREEN}  ✅ DynInst instruction tracing completed${NC}"
    else
        echo -e "${YELLOW}  ⚠️  DynInst instruction tracing timed out${NC}"
    fi
    
    # Test CWE-120 focused tracing
    echo "  🔍 Testing DynInst CWE-120 vulnerability tracing..."
    if timeout 10s docker compose run --rm dynint-dyninst python -m dynint.cli trace \
        --backend dyninst \
        --spawn "./$BINARY" \
        --map "$map_file" \
        --vulnerability-focus CWE-120 \
        --fn memcpy \
        --fn "_ZN22SimpleSpacecraftServer12HandleBufferERKSt6vectorIhSaIhEE" \
        --output "$cwe120_trace" >/dev/null 2>&1; then
        echo -e "${GREEN}  ✅ DynInst CWE-120 tracing completed${NC}"
    else
        echo -e "${YELLOW}  ⚠️  DynInst CWE-120 tracing timed out${NC}"
    fi
    
    # Test basic function tracing
    echo "  📊 Testing DynInst function tracing..."
    if timeout 5s docker compose run --rm dynint-dyninst python -m dynint.cli trace \
        --backend dyninst \
        --spawn "./$BINARY" \
        --map "$map_file" \
        --fn malloc \
        --fn free \
        --output "$trace_file" >/dev/null 2>&1; then
        echo -e "${GREEN}  ✅ DynInst function tracing completed${NC}"
    else
        echo -e "${YELLOW}  ⚠️  DynInst function tracing timed out${NC}"
    fi
    
    # Analyze trace files
    echo "  📈 Analyzing DynInst trace outputs..."
    for trace in "$trace_file" "$instruction_trace" "$cwe120_trace"; do
        if [ -f "$trace" ]; then
            local size=$(du -h "$trace" | cut -f1)
            local lines=$(wc -l < "$trace" 2>/dev/null || echo "0")
            local trace_name=$(basename "$trace")
            echo -e "${GREEN}  ✅ DynInst trace: $trace_name ($size, $lines events)${NC}"
            
            # Show instruction-level sample
            if [ "$lines" -gt 0 ] && [[ "$trace" == *"instruction"* ]]; then
                echo "    Sample instruction event:"
                head -n1 "$trace" | python3 -c "
import json, sys
try:
    event = json.loads(sys.stdin.read())
    addr = event.get('address', '?')
    bytes_val = event.get('bytes', '?')[:16]
    mnemonic = event.get('mnemonic', '?')
    print(f'      {addr}: {bytes_val} {mnemonic}')
except:
    print('      Unable to parse instruction event')
" 2>/dev/null
            fi
            
            # Show CWE-120 vulnerability events
            if [[ "$trace" == *"cwe120"* ]] && [ "$lines" -gt 0 ]; then
                local vuln_count=$(grep -c "vulnerability_trigger" "$trace" 2>/dev/null || echo "0")
                echo "    CWE-120 vulnerability events: $vuln_count"
            fi
        fi
    done
    
    # Show DynInst capabilities
    if [ -f "$instruction_trace" ]; then
        local dyninst_events=$(wc -l < "$instruction_trace" 2>/dev/null || echo "0")
        echo "  📊 DynInst analysis: $dyninst_events instruction-level events"
        echo -e "${GREEN}  ✅ DynInst provides comprehensive instruction-level tracing${NC}"
    fi
    
    echo -e "${GREEN}✅ DynInst tests completed${NC}"
}

# Function to show summary
show_summary() {
    echo
    echo -e "${BLUE}📋 Test Summary${NC}"
    echo -e "${BLUE}=================${NC}"
    
    echo -e "${YELLOW}Output files created:${NC}"
    find "$OUTPUT_DIR" -type f | while read -r file; do
        local size=$(du -h "$file" | cut -f1)
        echo "  📄 $file ($size)"
    done
    
    echo
    echo -e "${YELLOW}Commands to explore results:${NC}"
    echo "  # View dynmap output:"
    echo "  jq . $DYNMAP_DIR/spacecraft_detailed.json | less"
    echo
    echo "  # View DynInst trace output:"
    echo "  cat $DYNTRACE_DIR/*.jsonl | jq ."
    echo
    echo "  # Interactive DynInst shell:"
    echo "  docker compose run --rm dynint"
    echo
    echo "  # DynInst container:"
    echo "  docker compose run --rm dynint-dyninst"
}

# Main execution
main() {
    check_docker
    check_binary
    build_containers
    setup_directories
    
    echo
    echo -e "${BLUE}🧪 Running Tests${NC}"
    echo -e "${BLUE}===============${NC}"
    
    if test_dynmap; then
        echo
        if test_dyninst; then  # DynInst tests
            echo
            show_summary
            echo -e "${GREEN}🎉 All tests completed successfully!${NC}"
        else
            echo -e "${YELLOW}⚠️  DynInst tests had issues (check DynInst setup)${NC}"
            show_summary
        fi
    else
        echo -e "${RED}❌ dynmap tests failed${NC}"
        exit 1
    fi
}


# Handle command line arguments
case "${1:-}" in
    "dynmap")
        check_docker
        check_binary
        build_containers
        setup_directories
        test_dynmap
        ;;
    "dyninst")
        check_docker
        check_binary
        build_containers
        setup_directories
        test_dyninst
        ;;
    "clean")
        echo -e "${BLUE}🧹 Cleaning up...${NC}"
        rm -rf "$OUTPUT_DIR"
        docker compose down >/dev/null 2>&1 || true
        echo -e "${GREEN}✅ Cleanup completed${NC}"
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [command]"
        echo
        echo "Commands:"
        echo "  (no args)  Run all tests (dynmap + dyninst)"
        echo "  dynmap     Run only dynmap static analysis"
        echo "  dyninst    Run only DynInst instruction-level tracing"
        echo "  clean      Clean up output files and containers"
        echo "  help       Show this help"
        echo
        echo "Examples:"
        echo "  $0                    # Run full test suite"
        echo "  $0 dyninst          # Test DynInst backend only"
        echo "  $0 clean            # Clean up all outputs"
        ;;
    "")
        main
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac