# Quick Start - Spacecraft Vulnerability Tracer

## TL;DR - Run Now

```bash
cd /home/user/algebra-system/dynint/dynint
docker compose build
docker compose run --rm dynint-frida bash run_full_trace.sh
```

**That's it!** Results will be in `output/vulnerability_report.txt`

## What You Get

The tracer captures the **complete runtime execution path** showing how a malicious network packet reaches the vulnerability:

```
Network Packet (UDP)
    ↓ 0x35f5: recvfrom@plt
    ↓
Buffer [rbp-0x820]
    ↓ 0x3285: 🚨 READ service_type byte from packet[7]
    ↓ 0x3289: Store service_type → [rbp-0x68]
    ↓
ProcessPUSCommand called
    ↓ 0x3509: Load service_type from [rbp-0x68] → ESI
    ↓ 0x2d1d: Store ESI → [rbp-0xc]
    ↓
🚨 VULNERABILITY at 0x2e40:
    cmp [rbp-0xc], 0x0  ← ONLY checks if service_type == 0
    jne 2eb2            ← Malicious values (0xFF) bypass!
```

## Key Files Created

| File | Purpose |
|------|---------|
| `run_full_trace.sh` | **Run this** - Automated complete trace |
| `trace_vulnerability_path.py` | Python script - Manual tracing |
| `send_test_packet.py` | Send CCSDS/PUS test packets |
| `TRACE_VULNERABILITY_README.md` | Complete documentation |
| `USAGE_EXAMPLES.md` | Step-by-step examples |

## 3 Ways to Use

### 1. Fully Automated (Easiest)

```bash
docker compose run --rm dynint-frida bash run_full_trace.sh
```

### 2. Python Script

```bash
docker compose run --rm dynint-frida python trace_vulnerability_path.py --binary ./spacecraft_server_linux_x86
```

### 3. Manual Control

```bash
# Terminal 1: Start trace
docker compose run --rm dynint-frida \
    python -m dynint.cli trace \
    --spawn ./spacecraft_server_linux_x86 \
    --map output/map.json \
    --callsite 0x35f5 --callsite 0x3285 --callsite 0x2e40 \
    --fn recvfrom \
    --duration 15 &

# Terminal 2: Send packets (wait 3 sec)
sleep 3
docker compose run --rm dynint-frida \
    python send_test_packet.py --scenarios
```

## Output Location

```
output/
├── vulnerability_map.json       # Static analysis
├── vulnerability_trace.jsonl    # Raw trace data
└── vulnerability_report.txt     # Human-readable results
```

## What Gets Traced

**31 critical addresses** organized in 10 groups:

1. ✅ **RECVFROM_SETUP** (0x35f5) - Packet entry
2. ✅ **RECVFROM_RESULT** - Validate packet received
3. ✅ **PACKET_LOGGING** - Debug output
4. ✅ **PARSECCSDS_SETUP** - Parse CCSDS packet
5. ✅ **PUS_HEADER_CALC** - Calculate PUS header location
6. ✅ **PUS_VERSION** - Read PUS version byte
7. 🚨 **SERVICE_TYPE_READ** (0x3285, 0x3289) - **Read malicious byte**
8. ✅ **PROCESSPUS_SETUP** - Prepare command processing
9. ✅ **PROCESSPUS_PARAMS** - Pass parameters
10. 🚨 **CWE20_VULNERABILITY** (0x2e40, 0x2e44) - **Insufficient validation**

## Test Packets

The script sends these packets automatically:

| Packet | service_type | Expected Result |
|--------|--------------|-----------------|
| Valid | 0x01 | Normal processing |
| Edge | 0x00 | Rejected (== 0) |
| **Exploit** | **0xFF** | **Bypasses validation!** |
| **Exploit** | **0x80** | **Bypasses validation!** |

## Understanding Results

### ✅ Success Output

```
🚨 CRITICAL: Vulnerability path EXECUTED!
    The service_type byte was read from network packet
    and reached the insufficient validation at 0x2e40
```

### ❌ No Execution Detected

```
⚠️ WARNING: Vulnerability path NOT fully executed
   Missing groups: ['SERVICE_TYPE_READ', 'CWE20_VULNERABILITY']
```

**Fix**: Increase duration or ensure packets sent

## The Vulnerability (CWE-20)

**Problem:**
```c
if (service_type == 0) {
    return ERROR;
}
// NO upper bound check!
// service_type=255 is processed as valid!
```

**Assembly (0x2e40):**
```asm
cmp BYTE PTR [rbp-0xc],0x0  ; Only checks == 0
jne 2eb2                     ; If != 0, continue ← VULNERABLE
```

**Fix:**
```c
if (service_type == 0 || service_type > MAX_SERVICE_TYPE) {
    return ERROR;
}
```

## Customization

### Change Duration
```bash
export DURATION=30
bash run_full_trace.sh
```

### Custom Packet
```bash
python send_test_packet.py \
    --service-type 0xFF \
    --payload deadbeefcafe
```

### Different Port
```bash
export SERVER_PORT=6666
bash run_full_trace.sh
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No events captured | Increase duration: `DURATION=30` |
| Server not ready | Increase sleep in script |
| Permission denied | Use Docker (already configured) |
| Empty trace file | Check `/tmp/trace_log.txt` |

## View Trace Data

```bash
# Pretty print JSON
cat output/vulnerability_trace.jsonl | jq .

# Show only critical addresses
cat output/vulnerability_trace.jsonl | \
    jq 'select(.static == "0x3285" or .static == "0x2e40")'

# Count events
cat output/vulnerability_trace.jsonl | wc -l
```

## Parameters Reference

### trace_vulnerability_path.py

```
--binary PATH              Binary to trace (default: spacecraft_server_linux_x86)
--duration SECONDS         How long to trace (default: 10)
--map-output PATH          Where to save map file
--trace-output PATH        Where to save trace data
--report-output PATH       Where to save report
--skip-map                 Use existing map file
```

### send_test_packet.py

```
--host HOST                Target host (default: 127.0.0.1)
--port PORT                Target port (default: 5555)
--service-type BYTE        Service type (hex or decimal)
--scenarios                Send all test scenarios
--continuous               Keep sending packets
--interval SECONDS         Delay between packets
```

## Next Steps

1. ✅ **Run the trace** (you just did it!)
2. 📖 Read [TRACE_VULNERABILITY_README.md](TRACE_VULNERABILITY_README.md) for details
3. 🧪 Try [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md) for more scenarios
4. 🔧 Experiment with `send_test_packet.py` parameters
5. 📊 Analyze trace with `jq` or custom scripts

## Key Difference from objdump

| Static (objdump) | Dynamic (this tool) |
|-----------------|---------------------|
| Shows all code | Shows executed code only |
| No runtime data | Captures actual values |
| Can't trace PLT | Traces system calls |
| Manual analysis | Automated detection |

## Architecture

```
run_full_trace.sh (orchestrator)
    ↓
    ├── dynint.cli map (static analysis)
    │   └── Generates: output/vulnerability_map.json
    ↓
    ├── dynint.cli trace (Frida dynamic tracing)
    │   ├── Hooks 31 addresses
    │   ├── Hooks recvfrom, printf
    │   └── Generates: output/vulnerability_trace.jsonl
    ↓
    ├── send_test_packet.py (packet injection)
    │   └── Sends 4 test packets (0x01, 0x00, 0xFF, 0x80)
    ↓
    └── trace_vulnerability_path.py (analysis)
        └── Generates: output/vulnerability_report.txt
```

## Help

```bash
# Script help
python trace_vulnerability_path.py --help
python send_test_packet.py --help

# dynint help
python -m dynint.cli --help
python -m dynint.cli map --help
python -m dynint.cli trace --help
```

## Questions?

- 📖 [TRACE_VULNERABILITY_README.md](TRACE_VULNERABILITY_README.md) - Complete documentation
- 📝 [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md) - More examples
- 🇺🇦 [UKRAINIAN_GUIDE.md](UKRAINIAN_GUIDE.md) - Українською
