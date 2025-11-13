
# dynint

`dynint` provides a comprehensive toolkit for Linux ELF binaries powered by DynInst and multiple disassemblers (Angr, Capstone, OBJDump):

- `static` — static analyzer that enumerates functions, instructions, basic blocks, PLT callsites, and dynamic dependencies using multiple backends
- `dyntrace` — dynamic tracer built on **DynInst** for instruction-level runtime instrumentation

## Features

- ✅ **Multi-Disassembler Support**: Capstone (fast), Angr (advanced CFG), Objdump (universal)
- ✅ **Structured Exports**: Organized timestamped directories with separate component files
- ✅ **Intel x86-64 Assembly**: Complete instruction-level disassembly output
- ✅ **Behavior Algebra**: Mathematical representation of binary control flow
- ✅ **Comprehensive Analysis**: Functions, callsites, PLT entries, CFG data
- ✅ **Docker Integration**: Containerized analysis environment


## Docker Setup

Build and start containers:
```bash
docker compose build
docker compose up -d
```

## Usage

### Static analysis (`static`)

**Basic Commands:**
```bash
# List available backends
python -m dynint.cli static --list-backends

# Basic static analysis (single file)
python -m dynint.cli static ./binary -o static.json

# Structured export with separate files (recommended)
python -m dynint.cli static ./binary --structured --include-instructions --include-behavior-algebra
```

**Backend Selection:**
```bash
# Use Capstone backend (default - fast, reliable)
python -m dynint.cli static ./binary --backend capstone --structured

# Use Angr backend (advanced CFG analysis)
python -m dynint.cli static ./binary --backend angr --structured

# Use Objdump backend (universal compatibility)
python -m dynint.cli static ./binary --backend objdump --structured
```

**Analysis Options:**
```bash
# Include instruction-level disassembly
python -m dynint.cli static ./binary --structured --include-instructions

# Include behavior algebra generation
python -m dynint.cli static ./binary --structured --include-behavior-algebra

# Full analysis with all components
python -m dynint.cli static ./binary --structured --include-instructions --include-behavior-algebra --with-dwarf --bytes

# Only external PLT calls
python -m dynint.cli static ./binary --structured --only-extern-calls
```

**Docker Usage:**
```bash
# List available backends
docker compose run --rm dynint python -m dynint.cli static --list-backends

# Basic structured export
docker compose run --rm dynint python -m dynint.cli static ./binary --structured

# Full analysis with all backends
docker compose run --rm dynint python -m dynint.cli static ./binary --backend capstone --structured --include-instructions --include-behavior-algebra
docker compose run --rm dynint python -m dynint.cli static ./binary --backend angr --structured --include-instructions
docker compose run --rm dynint python -m dynint.cli static ./binary --backend objdump --structured

# Mount external binary
docker compose run --rm -v /path/to/binary:/data/binary dynint python -m dynint.cli static /data/binary --structured --include-instructions

# Custom output directory
docker compose run --rm dynint python -m dynint.cli static ./binary --structured --output /custom/output/dir
```

**Command Line Arguments:**
```
Required:
  binary                    Path to ELF binary to analyze

Output Options:
  -o, --output PATH         Output directory (structured) or file path (single)
  --structured              Create structured export with separate files [RECOMMENDED]

Backend Selection:
  --backend {capstone,angr,objdump}  Disassembler backend (default: capstone)
  --list-backends           List available backends and exit

Analysis Components:
  --include-instructions    Include instruction-level disassembly
  --include-behavior-algebra Include behavior algebra generation
  --with-dwarf             Include DWARF debugging information
  --bytes                  Include instruction bytes
  --only-extern-calls      Only analyze external function calls

Analysis Level:
  --analysis-level {symbols,basic-blocks}  Analysis granularity (default: basic-blocks)
```

### Structured Export Format

When using `--structured`, dynint creates a timestamped directory with organized component files:

```
output/static/
└── binary_backend_YYYYMMDD_HHMMSS/
    ├── analysis.json          # Complete analysis (legacy format)
    ├── functions.json         # Functions and callsites
    ├── instructions.json      # Instruction-level disassembly (if --include-instructions)
    ├── behavior_algebra.txt   # Behavior algebra expressions (if --include-behavior-algebra)
    └── summary.txt           # Human-readable analysis summary
```

**Example Output:**
```
spacecraft_server_linux_x86_capstone_20251113_114111/
├── analysis.json          # 62.8 MB - Complete analysis
├── functions.json         # 2.9 MB  - 5,609 functions, 17,577 callsites
├── instructions.json      # 53.0 MB - 367,966 Intel x86-64 instructions
├── behavior_algebra.txt   # 6.7 MB  - 95,267 mathematical expressions
└── summary.txt           # 445 B   - Analysis statistics
```

**File Contents:**

- **`functions.json`**: Function metadata, callsites, PLT entries, binary info
- **`instructions.json`**: Complete instruction disassembly in Intel x86-64 format
- **`behavior_algebra.txt`**: Mathematical behavior algebra expressions
- **`analysis.json`**: Legacy complete format for backward compatibility
- **`summary.txt`**: Human-readable statistics and file inventory

### Backend Comparison

| Backend | Speed | Functions Found | Features | Use Case |
|---------|--------|----------------|----------|----------|
| **Capstone** | Fast | ~5,600 | Instruction disassembly, callsites | Production analysis |
| **Angr** | Slow | ~21,000 | Advanced CFG, symbolic execution | Research, complex analysis |
| **Objdump** | Medium | ~5,600 | Universal compatibility | Cross-platform, verification |

### Sample Output

**Intel x86-64 Instructions (instructions.json):**
```json
{
  "instructions": [
    {"address": "401000", "mnemonic": "endbr64", "operands": "", "size": 4},
    {"address": "401004", "mnemonic": "sub", "operands": "rsp, 8", "size": 4}, 
    {"address": "401008", "mnemonic": "mov", "operands": "rax, 0", "size": 7},
    {"address": "40100f", "mnemonic": "test", "operands": "rax, rax", "size": 3},
    {"address": "401012", "mnemonic": "je", "operands": "0x401016", "size": 2}
  ],
  "total_instructions": 367966
}
```

**Behavior Algebra (behavior_algebra.txt):**
```
B(401000) = endbr64(401000).sub(401004).mov(401008).test(40100f).je(401012).B(401014),
B(401014) = B(rax); B(401016),
B(401016) = add(401016).ret(40101a).B(401020),
B(401020) = endbr64(401020).bnd jmp(401024).nop(40102b).B(401030),
```

**Functions (functions.json):**
```json
{
  "functions": [
    {
      "name": "main",
      "addr": "0x404670", 
      "size": 142,
      "bind": "STB_GLOBAL",
      "section": "14"
    }
  ],
  "callsites": [
    {
      "at_addr": "0x401014",
      "type": "call", 
      "target": "rax",
      "size": 2
    }
  ]
}
```

### Dynamic tracing (`dyntrace`)

**Instruction-level tracing:**
```bash
# Comprehensive instruction-level analysis with machine code
python -m dynint.cli trace --spawn ./binary --map static.json --instruction-level --memory-access

# CWE-120 vulnerability analysis
python -m dynint.cli trace --spawn ./binary --map static.json --vulnerability-focus CWE-120 --instruction-level

# Function tracing with machine code bytes
python -m dynint.cli trace --spawn ./binary --map static.json --fn memcpy --fn strcpy --instruction-level
```

**Docker usage:**
```bash
# Spawn with instruction-level tracing
docker compose run --rm dynint python -m dynint.cli trace --spawn ./binary --map static.json --instruction-level

# Vulnerability-focused analysis  
docker compose run --rm dynint python -m dynint.cli trace --spawn ./spacecraft_server_linux_x86 --map static.json --vulnerability-focus CWE-120 --instruction-level --memory-access
```


# With sampling and time limits
python -m dynint.cli trace --spawn ./binary --map static.json --fn malloc --sample 1/10 --duration 30.0
```

**Docker usage:**
```bash
# Basic spawn mode
docker compose run --rm dynint-frida python -m dynint.cli trace --spawn ./binary --map static.json --fn malloc

# With output file
docker compose run --rm dynint-frida python -m dynint.cli trace --spawn ./binary --map static.json --fn malloc --output output/trace.jsonl

# Mount external binary and map
docker compose run --rm -v /path/to/binary:/data/binary -v /path/to/static.json:/data/static.json dynint-frida python -m dynint.cli trace --spawn /data/binary --map /data/static.json --fn malloc

# Parameters:
# --pid PID         Attach to running process
# --spawn BINARY    Launch new process 
# --map STATIC.json    Static analysis file
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

# 2. Generate comprehensive static analysis
docker compose run --rm dynint python -m dynint.cli static ./spacecraft_server_linux_x86 --structured --include-instructions --include-behavior-algebra --backend capstone

# 3. Run dynamic trace
docker compose run --rm dynint python -m dynint.cli trace --spawn ./spacecraft_server_linux_x86 --map output/static.json --fn malloc --output output/trace.jsonl
```

## Common Usage Patterns

**Research & Analysis:**
```bash
# Complete analysis with all backends for comparison
docker compose run --rm dynint python -m dynint.cli static ./binary --backend capstone --structured --include-instructions --include-behavior-algebra
docker compose run --rm dynint python -m dynint.cli static ./binary --backend angr --structured --include-instructions  
docker compose run --rm dynint python -m dynint.cli static ./binary --backend objdump --structured
```

**Production Analysis:**
```bash
# Fast analysis for CI/CD pipelines
docker compose run --rm dynint python -m dynint.cli static ./binary --backend capstone --structured --include-instructions
```

**Cross-Platform Verification:**
```bash
# Universal compatibility check
docker compose run --rm dynint python -m dynint.cli static ./binary --backend objdump --structured
```

**Behavior Analysis:**
```bash
# Mathematical behavior modeling
docker compose run --rm dynint python -m dynint.cli static ./binary --backend capstone --structured --include-behavior-algebra
```
