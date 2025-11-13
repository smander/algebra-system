"""Command line interface for dynint."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import static
from .dyntrace import runner


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dynint", description="Binary mapping and dynamic tracing toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    static_parser = subparsers.add_parser("static", help="Generate static mapping information for an ELF binary")
    static_parser.add_argument("binary", type=Path, nargs="?", help="Path to the ELF binary to analyze")
    static_parser.add_argument("--output", "-o", type=Path, default=Path("output/static"), help="Output directory (for structured) or JSON path (for single file)")
    static_parser.add_argument("--structured", action="store_true", help="Create structured export with separate files in timestamped directory")
    static_parser.add_argument("--only-extern-calls", action="store_true", help="Emit only external callsites in the static analysis")
    static_parser.add_argument("--with-dwarf", action="store_true", help="Include DWARF file:line info where available")
    static_parser.add_argument("--bytes", action="store_true", help="Include instruction bytes for callsites")
    static_parser.add_argument("--analysis-level", choices=["symbols", "basic-blocks"], default="basic-blocks",
                            help="Granularity of control flow extraction")
    static_parser.add_argument("--backend", choices=["capstone", "angr", "objdump"], default="capstone",
                            help="Disassembler backend to use (default: capstone)")
    static_parser.add_argument("--include-instructions", action="store_true",
                            help="Include instruction-level disassembly in output")
    static_parser.add_argument("--include-behavior-algebra", action="store_true",
                            help="Generate behavior algebra representation")
    static_parser.add_argument("--list-backends", action="store_true",
                            help="List available disassembler backends and exit")

    trace_parser = subparsers.add_parser("trace", help="Trace runtime activity of a process using map information")
    trace_parser.add_argument("--pid", type=int, help="PID of the process to attach to")
    trace_parser.add_argument("--spawn", type=Path, help="Binary to spawn under instrumentation")
    trace_parser.add_argument("--args", nargs=argparse.REMAINDER, help="Arguments for spawned binary")
    trace_parser.add_argument("--map", type=Path, required=True, help="Path to previously generated static.json")
    trace_parser.add_argument("--backend", choices=["dyninst", "bcc"], default="dyninst",
                              help="Dynamic tracing backend to use (default: dyninst)")
    trace_parser.add_argument("--lib", action="append", dest="libs", help="Library soname(s) to trace")
    trace_parser.add_argument("--fn", action="append", dest="functions", help="Specific function name(s) to trace")
    trace_parser.add_argument("--callsite", action="append", dest="callsites", help="Calls site addresses to trace")
    trace_parser.add_argument("--output", type=Path, help="Write JSONL trace to file instead of stdout")
    trace_parser.add_argument("--sample", type=str, help="Sampling spec like 1/100 to keep 1 in every 100 calls")
    trace_parser.add_argument("--since", type=float, help="Ignore events before this timestamp (seconds)")
    trace_parser.add_argument("--duration", type=float, help="Stop tracing after duration seconds")
    
    # DynInst-specific arguments
    trace_parser.add_argument("--instruction-level", action="store_true",
                             help="Enable instruction-level tracing with machine code")
    trace_parser.add_argument("--memory-access", action="store_true",
                             help="Trace memory access instructions")
    trace_parser.add_argument("--control-flow", action="store_true",
                             help="Trace control flow changes")
    trace_parser.add_argument("--vulnerability-focus", choices=["CWE-120", "CWE-20"],
                             help="Focus on specific vulnerability patterns")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "static":
        # List available backends if requested
        if args.list_backends:
            available = static.get_available_backends()
            print("Available disassembler backends:")
            for backend in available:
                print(f"  - {backend}")
            print(f"\nDefault: {args.backend}")
            return 0
        
        # Ensure binary is provided when not just listing backends
        if not args.binary:
            print("Error: binary path is required when not using --list-backends")
            return 1
        
        # Validate backend availability
        available_backends = static.get_available_backends()
        if args.backend not in available_backends:
            print(f"Error: Backend '{args.backend}' is not available.")
            print(f"Available backends: {available_backends}")
            print("Install required dependencies or use a different backend.")
            return 1
        
        try:
            if args.structured:
                # Use structured export
                export_dir = static.export_structured_analysis(
                    binary_path=args.binary,
                    output_base_dir=args.output,
                    only_external_calls=args.only_extern_calls,
                    include_dwarf=args.with_dwarf,
                    include_bytes=args.bytes,
                    analysis_level=args.analysis_level,
                    backend=args.backend,
                    include_instructions=args.include_instructions,
                    include_behavior_algebra=args.include_behavior_algebra,
                )
                
                print(f"[+] Analysis completed using {args.backend} backend")
                print(f"[+] Structured export created in: {export_dir}")
                
                # Read summary for stats
                summary_file = export_dir / "summary.txt"
                if summary_file.exists():
                    summary_lines = summary_file.read_text().splitlines()
                    # Print key stats from summary
                    for line in summary_lines:
                        if line.startswith(("Functions:", "Callsites:", "Instructions:", "Files created:")):
                            print(f"[+] {line}")
                
                return 0
            else:
                # Use legacy single file export
                mapping = static.generate_map(
                    binary_path=args.binary,
                    only_external_calls=args.only_extern_calls,
                    include_dwarf=args.with_dwarf,
                    include_bytes=args.bytes,
                    analysis_level=args.analysis_level,
                    backend=args.backend,
                    include_instructions=args.include_instructions,
                    include_behavior_algebra=args.include_behavior_algebra,
                )
                
                args.output.write_text(json.dumps(mapping, indent=2))
                print(f"[+] Analysis completed using {args.backend} backend")
                print(f"[+] Static analysis written to {args.output}")
                
                # Print summary stats
                functions_count = len(mapping.get("functions", []))
                instructions_count = len(mapping.get("instructions", []))
                callsites_count = len(mapping.get("callsites", []))
                
                print(f"[+] Found {functions_count} functions, {callsites_count} callsites")
                if args.include_instructions:
                    print(f"[+] Disassembled {instructions_count} instructions")
                if args.include_behavior_algebra and mapping.get("behavior_algebra"):
                    algebra_lines = mapping["behavior_algebra"].count('\n')
                    print(f"[+] Generated behavior algebra with {algebra_lines} expressions")
                
                return 0
        
        except Exception as e:
            print(f"Error during analysis: {e}")
            return 1

    if args.command == "trace":
        result = runner.run_trace(
            backend=args.backend,
            map_path=args.map,
            pid=args.pid,
            spawn=args.spawn,
            spawn_args=args.args,
            libs=args.libs,
            functions=args.functions,
            callsites=args.callsites,
            output_path=args.output,
            sample=args.sample,
            since=args.since,
            duration=args.duration,
            # DynInst options
            instruction_level=getattr(args, 'instruction_level', False),
            memory_access=getattr(args, 'memory_access', False),
            control_flow=getattr(args, 'control_flow', False),
            vulnerability_focus=getattr(args, 'vulnerability_focus', None),
        )
        return 0 if result else 1

    parser.error("unknown command")
    return 1


def main_static() -> int:
    return main(["static", *sys.argv[1:]])


def main_trace() -> int:
    return main(["trace", *sys.argv[1:]])


if __name__ == "__main__":
    sys.exit(main())
