
# dynint

`dynint` provides a two-mode toolkit for Linux ELF binaries:

- `dynmap` — static analyzer that enumerates functions, basic blocks, PLT callsites, and dynamic dependencies
- `dyntrace` — dynamic tracer built on Frida for runtime instrumentation

## 🚨 Spacecraft Server Vulnerability Tracer

**NEW**: Complete solution for tracing the execution path from `recvfrom` network packet reception to the CWE-20 input validation vulnerability.

**Quick Start:**
```bash
# Run automated trace (Docker)
docker compose run --rm dynint-frida bash run_full_trace.sh

# View results
docker compose run --rm dynint-frida cat output/vulnerability_report.txt
```

**Documentation:**
- 📖 [Complete Guide](TRACE_VULNERABILITY_README.md) - Detailed documentation
- 📝 [Usage Examples](USAGE_EXAMPLES.md) - Step-by-step examples
- 🇺🇦 [Ukrainian Guide](UKRAINIAN_GUIDE.md) - Українською мовою

**What it does:**
- Traces **actual runtime execution** from network packet entry to vulnerability point
- Captures all 31 critical machine instructions along the path
- Shows data flow of the malicious `service_type` byte through memory
- Confirms vulnerability exploitation with packet testing

---

## Docker Setup

Build and start containers:
```bash
docker compose build
docker compose up -d
```

## Usage

### Static analysis (`dynmap`)

**Direct usage:**
```bash
# Basic static analysis
python -m dynint.cli map ./binary -o map.json

# With debug info and callsite bytes
python -m dynint.cli map ./binary -o map.json --with-dwarf --bytes

# Only PLT calls
python -m dynint.cli map ./binary -o map.json --only-extern-calls
```

**Docker usage:**
```bash
# Basic analysis
docker compose run --rm dynint-frida python -m dynint.cli map ./binary -o output/map.json

# Mount external binary
docker compose run --rm -v /path/to/binary:/data/binary dynint-frida python -m dynint.cli map /data/binary -o output/map.json
```

### Dynamic tracing (`dyntrace`)

**Direct usage:**
```bash
# Attach to existing process
python -m dynint.cli trace --pid 1234 --map map.json --fn malloc --fn free

# Spawn new process
python -m dynint.cli trace --spawn ./binary --map map.json --fn recv --fn send

# Trace specific library
python -m dynint.cli trace --spawn ./binary --map map.json --lib libc.so.6

# With sampling and time limits
python -m dynint.cli trace --spawn ./binary --map map.json --fn malloc --sample 1/10 --duration 30.0
```

**Docker usage:**
```bash
# Basic spawn mode
docker compose run --rm dynint-frida python -m dynint.cli trace --spawn ./binary --map map.json --fn malloc

# With output file
docker compose run --rm dynint-frida python -m dynint.cli trace --spawn ./binary --map map.json --fn malloc --output output/trace.jsonl

# Mount external binary and map
docker compose run --rm -v /path/to/binary:/data/binary -v /path/to/map.json:/data/map.json dynint-frida python -m dynint.cli trace --spawn /data/binary --map /data/map.json --fn malloc

# Parameters:
# --pid PID         Attach to running process
# --spawn BINARY    Launch new process 
# --map MAP.json    Static analysis map file
# --fn FUNCTION     Function to trace (multiple allowed)
# --lib LIBRARY     Library to trace (traces all functions)
# --sample 1/N      Sample 1 out of N events
# --duration SEC    Stop after N seconds
# --output FILE     Write JSONL to file
```

## Quick Start

```bash
# 1. Build Docker containers
docker compose build

# 2. Generate static analysis map
docker compose run --rm dynint-frida python -m dynint.cli map ./spacecraft_server_linux_x86 -o output/map.json

# 3. Run dynamic trace
docker compose run --rm dynint-frida python -m dynint.cli trace --spawn ./spacecraft_server_linux_x86 --map output/map.json --fn malloc --output output/trace.jsonl
```
