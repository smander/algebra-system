# Usage Examples - Spacecraft Vulnerability Tracer

## Complete Examples for Tracing recvfrom → CWE-20 Path

### Example 1: Docker - Automated Full Trace (Easiest)

```bash
# Navigate to the dynint directory
cd /home/user/algebra-system/dynint/dynint

# Build Docker containers (first time only)
docker compose build

# Run complete automated trace
docker compose run --rm dynint-frida bash run_full_trace.sh

# View the results
docker compose run --rm dynint-frida cat output/vulnerability_report.txt
```

**Expected Output:**
```
================================================================================
VULNERABILITY PATH TRACE: recvfrom → CWE-20
================================================================================

📍 RECVFROM_SETUP
--------------------------------------------------------------------------------
   1. 0x35f5: call recvfrom@plt
      Runtime addr: 0x5555557c35f5
      Thread ID: 12345

📍 SERVICE_TYPE_READ
--------------------------------------------------------------------------------
  22. 0x3285: 🚨 movzx eax,BYTE PTR[rax+0x1] - READ service_type from network
      Runtime addr: 0x5555557c3285
  23. 0x3289: 🚨 mov [rbp-0x68],al - store service_type
      Runtime addr: 0x5555557c3289

📍 CWE20_VULNERABILITY
--------------------------------------------------------------------------------
  30. 0x2e40: 🚨 cmp [rbp-0xc],0x0 - CWE-20: Compare service_type with 0
      Runtime addr: 0x5555557c2e40
  31. 0x2e44: 🚨 jne 2eb2 - EXPLOITED: malicious command processed
      Runtime addr: 0x5555557c2e44

🚨 CRITICAL: Vulnerability path EXECUTED!
```

### Example 2: Docker - Step by Step Manual Control

```bash
cd /home/user/algebra-system/dynint/dynint

# Step 1: Generate static map
docker compose run --rm dynint-frida \
    python -m dynint.cli map ./spacecraft_server_linux_x86 \
    --output output/map.json \
    --with-dwarf \
    --bytes

# Step 2: In one terminal - Start trace
docker compose run --rm dynint-frida \
    python trace_vulnerability_path.py \
    --binary ./spacecraft_server_linux_x86 \
    --duration 20

# Step 3: In another terminal - Send packets (wait 3 seconds after starting trace)
docker compose run --rm dynint-frida \
    python send_test_packet.py --scenarios

# Step 4: View results (after trace completes)
docker compose run --rm dynint-frida \
    cat output/vulnerability_report.txt
```

### Example 3: Direct Python Script (No Shell Script)

```bash
cd /home/user/algebra-system/dynint/dynint

# One-command trace with packet sending
python trace_vulnerability_path.py \
    --binary ./spacecraft_server_linux_x86 \
    --duration 15 \
    --map-output output/map.json \
    --trace-output output/trace.jsonl \
    --report-output output/report.txt &

# Wait for server to start
sleep 3

# Send test packets
python send_test_packet.py --scenarios

# Wait for trace to complete
wait

# View results
cat output/report.txt
```

### Example 4: Custom Packet Testing

```bash
# Send single exploit packet
docker compose run --rm dynint-frida \
    python send_test_packet.py \
    --service-type 0xFF \
    --service-subtype 0x01 \
    --payload deadbeef

# Send multiple custom packets
docker compose run --rm dynint-frida \
    python send_test_packet.py \
    --service-type 0x80 \
    --continuous \
    --interval 2.0 \
    --count 5

# Send all pre-defined scenarios
docker compose run --rm dynint-frida \
    python send_test_packet.py --scenarios
```

### Example 5: Trace Specific Addresses Only

```bash
# Trace only the critical vulnerability addresses
docker compose run --rm dynint-frida \
    python -m dynint.cli trace \
    --spawn ./spacecraft_server_linux_x86 \
    --map output/map.json \
    --callsite 0x35f5 \
    --callsite 0x3285 \
    --callsite 0x3289 \
    --callsite 0x2e40 \
    --callsite 0x2e44 \
    --fn recvfrom \
    --output output/critical_only.jsonl \
    --duration 15 &

# Send packets
sleep 3
docker compose run --rm dynint-frida \
    python send_test_packet.py --service-type 0xFF

wait
```

### Example 6: Analyzing Existing Trace Data

```bash
# If you already have a trace file, just run analysis
docker compose run --rm dynint-frida \
    python -c "
from trace_vulnerability_path import analyze_trace
from pathlib import Path
analyze_trace(Path('output/vulnerability_trace.jsonl'), Path('output/new_report.txt'))
"
```

### Example 7: Extended Tracing with Continuous Packets

```bash
# Terminal 1: Start long-running trace (60 seconds)
docker compose run --rm dynint-frida \
    python trace_vulnerability_path.py \
    --binary ./spacecraft_server_linux_x86 \
    --duration 60 &

sleep 3

# Terminal 2: Send continuous packets
docker compose run --rm dynint-frida \
    python send_test_packet.py \
    --continuous \
    --interval 3.0 \
    --count 15 \
    --service-type 0xFF

wait
```

### Example 8: Trace with Sampling (Reduce Output Size)

```bash
# Sample 1 out of every 10 events
docker compose run --rm dynint-frida \
    python -m dynint.cli trace \
    --spawn ./spacecraft_server_linux_x86 \
    --map output/map.json \
    --callsite 0x35f5 \
    --callsite 0x3285 \
    --callsite 0x2e40 \
    --fn recvfrom \
    --sample 1/10 \
    --output output/sampled_trace.jsonl \
    --duration 20 &

sleep 3
docker compose run --rm dynint-frida \
    python send_test_packet.py --scenarios

wait
```

## Interpreting Results

### Success Indicators

✅ **Trace captured the vulnerability path if you see:**
- `🚨 CRITICAL: Vulnerability path EXECUTED!`
- Both `SERVICE_TYPE_READ` and `CWE20_VULNERABILITY` groups present
- Events for addresses 0x3285 and 0x2e40

### What Each Address Means

| Address | What Happens |
|---------|-------------|
| 0x35f5  | Packet enters from network via recvfrom() |
| 0x3285  | **service_type byte read from packet** (buffer[7]) |
| 0x3289  | service_type stored in local variable |
| 0x3509  | service_type loaded as function parameter |
| 0x2e40  | **Insufficient validation** (only checks == 0) |
| 0x2e44  | Malicious value bypasses check |

### Example Trace Event

```json
{
  "kind": "callsite",
  "static": "0x3285",
  "runtime": "0x5555557c3285",
  "target": "movzx",
  "size": 4,
  "tid": 12345,
  "ts": 1699564123.456789
}
```

**Explanation:**
- `static`: Original address in binary (from objdump)
- `runtime`: Actual memory address during execution (with ASLR)
- `target`: Instruction mnemonic
- `tid`: Thread ID that executed this
- `ts`: Unix timestamp when executed

## Common Issues and Solutions

### Issue: No events captured

**Solution 1**: Increase trace duration
```bash
docker compose run --rm dynint-frida \
    bash run_full_trace.sh
# Edit DURATION=30 in the script
```

**Solution 2**: Check server started
```bash
# Monitor server in separate terminal
docker compose run --rm dynint-frida \
    ./spacecraft_server_linux_x86
# Should show: "Server listening on port 5555"
```

**Solution 3**: Verify packets sent
```bash
# Run packet sender with verbose output
docker compose run --rm dynint-frida \
    python send_test_packet.py --scenarios
# Should show: "✅ Sent successfully" for each packet
```

### Issue: Server not listening

**Solution**: Increase startup delay
```bash
# In run_full_trace.sh, change:
sleep 3
# to:
sleep 5
```

### Issue: Frida permission errors

**Solution**: Use Docker (pre-configured)
```bash
docker compose run --rm dynint-frida bash run_full_trace.sh
```

## Output Files Reference

### `output/vulnerability_map.json`
- Static analysis of binary
- All functions, basic blocks, callsites
- Used by tracer to map runtime addresses

### `output/vulnerability_trace.jsonl`
- Line-delimited JSON (one event per line)
- All traced function calls and callsite executions
- Can be processed with `jq` or custom scripts

### `output/vulnerability_report.txt`
- Human-readable summary
- Organized by execution stage
- Shows if vulnerability path executed
- Statistics and timing

## Advanced: Custom Analysis

### Parse Trace with jq

```bash
# Show all callsite events
cat output/vulnerability_trace.jsonl | jq 'select(.kind == "callsite")'

# Show only critical addresses
cat output/vulnerability_trace.jsonl | \
    jq 'select(.static == "0x3285" or .static == "0x2e40")'

# Count events by type
cat output/vulnerability_trace.jsonl | jq '.kind' | sort | uniq -c

# Show function call arguments
cat output/vulnerability_trace.jsonl | \
    jq 'select(.kind == "function") | {function, args}'
```

### Extract Timing Information

```bash
# Show execution timeline
cat output/vulnerability_trace.jsonl | \
    jq -r '[.ts, .kind, .static // .function] | @tsv' | \
    sort -n
```

## Environment Variables

```bash
# Customize run_full_trace.sh
export BINARY="./my_custom_server"
export DURATION=30
export SERVER_PORT=6666
export MAP_FILE="output/custom_map.json"

bash run_full_trace.sh
```

## Integration with CI/CD

```yaml
# .gitlab-ci.yml example
test_vulnerability_trace:
  image: dynint-frida
  script:
    - cd dynint
    - bash run_full_trace.sh
    - grep "CRITICAL: Vulnerability path EXECUTED" output/vulnerability_report.txt
  artifacts:
    paths:
      - dynint/output/
    expire_in: 1 week
```

## Next Steps

1. **Understand the vulnerability**: Read TRACE_VULNERABILITY_README.md
2. **Run your first trace**: Use Example 1 (Docker automated)
3. **Examine the results**: Check output/vulnerability_report.txt
4. **Experiment with packets**: Use send_test_packet.py with different service_type values
5. **Analyze the trace**: Use jq to explore the JSONL trace data
6. **Fix the vulnerability**: Add proper input validation (service_type range check)

## Support

For issues or questions:
- Check TRACE_VULNERABILITY_README.md for detailed documentation
- Review Docker logs: `docker compose logs`
- Examine trace log: `cat /tmp/trace_log.txt`
- Verify binary: `file spacecraft_server_linux_x86`
