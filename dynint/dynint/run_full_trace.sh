#!/bin/bash
#
# Complete orchestration script for tracing the vulnerability path
# from recvfrom to CWE-20 in the spacecraft server.
#
# This script:
# 1. Generates static map if needed
# 2. Starts dynamic trace in background
# 3. Waits for server to be ready
# 4. Sends test packets to trigger vulnerability path
# 5. Waits for trace to complete
# 6. Analyzes and reports results

set -e

# Configuration
BINARY="${BINARY:-./spacecraft_server_linux_x86}"
MAP_FILE="${MAP_FILE:-output/vulnerability_map.json}"
TRACE_FILE="${TRACE_FILE:-output/vulnerability_trace.jsonl}"
REPORT_FILE="${REPORT_FILE:-output/vulnerability_report.txt}"
DURATION="${DURATION:-15}"
SERVER_PORT="${SERVER_PORT:-5555}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
echo "================================================================================"
echo "  SPACECRAFT SERVER VULNERABILITY PATH TRACER - FULL EXECUTION"
echo "================================================================================"
echo ""
log_info "Configuration:"
echo "  Binary:     $BINARY"
echo "  Map file:   $MAP_FILE"
echo "  Trace file: $TRACE_FILE"
echo "  Report:     $REPORT_FILE"
echo "  Duration:   ${DURATION}s"
echo "  Port:       $SERVER_PORT"
echo "================================================================================"
echo ""

# Check binary exists
if [ ! -f "$BINARY" ]; then
    log_error "Binary not found: $BINARY"
    exit 1
fi

# Create output directory
mkdir -p output

# Step 1: Generate map if needed
if [ ! -f "$MAP_FILE" ] || [ "${REGEN_MAP:-0}" = "1" ]; then
    log_info "[1/6] Generating static analysis map..."
    python -m dynint.cli map "$BINARY" \
        --output "$MAP_FILE" \
        --with-dwarf \
        --bytes \
        --analysis-level basic-blocks
    log_success "Map generated: $MAP_FILE"
else
    log_info "[1/6] Using existing map: $MAP_FILE"
fi
echo ""

# Step 2: Prepare trace
log_info "[2/6] Preparing dynamic trace..."

# Build callsite list
CALLSITES=(
    # RECVFROM_SETUP
    "0x35f5"
    # RECVFROM_RESULT
    "0x35fa" "0x3601" "0x3609"
    # PACKET_LOGGING
    "0x37c9" "0x37d1" "0x37d9" "0x37dc" "0x37ed"
    # PARSECCSDS_SETUP
    "0x384c" "0x3853" "0x385a" "0x3861" "0x3864" "0x3867"
    # PUS_HEADER_CALC
    "0x326f" "0x3273" "0x3277"
    # PUS_VERSION
    "0x327b" "0x327e" "0x3281"
    # SERVICE_TYPE_READ (CRITICAL)
    "0x3285" "0x3289"
    # PROCESSPUS_SETUP
    "0x3505" "0x3509" "0x3515" "0x351b"
    # PROCESSPUS_PARAMS
    "0x2d1b" "0x2d1d"
    # CWE20_VULNERABILITY (CRITICAL)
    "0x2e40" "0x2e44"
)

# Build function list
FUNCTIONS=(
    "recvfrom"
    "printf"
)

log_info "  Tracing ${#CALLSITES[@]} callsites"
log_info "  Tracing ${#FUNCTIONS[@]} functions"
echo ""

# Step 3: Start trace in background
log_info "[3/6] Starting dynamic trace (${DURATION}s duration)..."

# Build command
CMD="python -m dynint.cli trace \
    --spawn \"$BINARY\" \
    --map \"$MAP_FILE\" \
    --output \"$TRACE_FILE\" \
    --duration $DURATION"

# Add callsites
for addr in "${CALLSITES[@]}"; do
    CMD="$CMD --callsite $addr"
done

# Add functions
for fn in "${FUNCTIONS[@]}"; do
    CMD="$CMD --fn $fn"
done

# Execute trace in background
log_info "  Starting trace process..."
eval "$CMD" > /tmp/trace_log.txt 2>&1 &
TRACE_PID=$!

log_info "  Trace process started (PID: $TRACE_PID)"
echo ""

# Step 4: Wait for server to start
log_info "[4/6] Waiting for server to start..."
sleep 3

# Check if server is listening
if ! nc -z -w2 127.0.0.1 $SERVER_PORT 2>/dev/null; then
    log_warning "  Server might not be listening on port $SERVER_PORT yet..."
    log_info "  Waiting additional 2 seconds..."
    sleep 2
fi

log_success "Server should be ready"
echo ""

# Step 5: Send test packets
log_info "[5/6] Sending test packets..."

# Send scenarios to trigger vulnerability path
log_info "  Sending malicious packet scenarios..."

# Scenario 1: Valid packet
log_info "    [1/4] Valid service_type=0x01"
python send_test_packet.py --host 127.0.0.1 --port $SERVER_PORT \
    --service-type 0x01 --service-subtype 0x12 2>/dev/null || true
sleep 1

# Scenario 2: Zero service_type (edge case)
log_info "    [2/4] Edge case service_type=0x00"
python send_test_packet.py --host 127.0.0.1 --port $SERVER_PORT \
    --service-type 0x00 --service-subtype 0x01 2>/dev/null || true
sleep 1

# Scenario 3: Exploit with service_type=0xFF
log_info "    [3/4] EXPLOIT service_type=0xFF (255)"
python send_test_packet.py --host 127.0.0.1 --port $SERVER_PORT \
    --service-type 0xFF --service-subtype 0x01 --payload "deadbeef" 2>/dev/null || true
sleep 1

# Scenario 4: Another exploit with service_type=0x80
log_info "    [4/4] EXPLOIT service_type=0x80 (128)"
python send_test_packet.py --host 127.0.0.1 --port $SERVER_PORT \
    --service-type 0x80 --service-subtype 0x02 --payload "cafebabe" 2>/dev/null || true

log_success "Test packets sent"
echo ""

# Step 6: Wait for trace to complete
log_info "[6/6] Waiting for trace to complete..."

# Calculate remaining time
ELAPSED=7  # Approximate time spent
REMAINING=$((DURATION - ELAPSED))

if [ $REMAINING -gt 0 ]; then
    log_info "  Waiting ${REMAINING} more seconds..."
    for i in $(seq 1 $REMAINING); do
        sleep 1
        echo -n "."
    done
    echo ""
fi

# Wait for trace process to finish
wait $TRACE_PID 2>/dev/null || true

log_success "Trace completed"
echo ""

# Step 7: Check if trace file exists and has data
if [ ! -f "$TRACE_FILE" ]; then
    log_error "Trace file not generated: $TRACE_FILE"
    log_info "Check trace log:"
    cat /tmp/trace_log.txt
    exit 1
fi

LINE_COUNT=$(wc -l < "$TRACE_FILE")
if [ "$LINE_COUNT" -eq 0 ]; then
    log_warning "Trace file is empty"
    log_info "Check trace log:"
    cat /tmp/trace_log.txt
    exit 1
fi

log_success "Trace file contains $LINE_COUNT events"
echo ""

# Step 8: Analyze trace
log_info "Analyzing trace..."
python trace_vulnerability_path.py \
    --binary "$BINARY" \
    --map-output "$MAP_FILE" \
    --trace-output "$TRACE_FILE" \
    --report-output "$REPORT_FILE" \
    --skip-map \
    --duration 0 2>&1 | grep -A 1000 "VULNERABILITY PATH TRACE" || {
        log_warning "Analysis completed but no vulnerability path detected"
    }

echo ""
echo "================================================================================"
log_success "COMPLETE!"
echo "================================================================================"
echo ""
echo "Results:"
echo "  - Static map:     $MAP_FILE"
echo "  - Trace data:     $TRACE_FILE ($LINE_COUNT events)"
echo "  - Report:         $REPORT_FILE"
echo "  - Trace log:      /tmp/trace_log.txt"
echo ""
echo "View the report:"
echo "  cat $REPORT_FILE"
echo ""
echo "View trace events:"
echo "  cat $TRACE_FILE | jq ."
echo ""
echo "================================================================================"
