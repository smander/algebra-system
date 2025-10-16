"""Command line interface for dynint."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import dynmap
from .dyntrace import runner


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dynint", description="Binary mapping and dynamic tracing toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    map_parser = subparsers.add_parser("map", help="Generate static mapping information for an ELF binary")
    map_parser.add_argument("binary", type=Path, help="Path to the ELF binary to analyze")
    map_parser.add_argument("--output", "-o", type=Path, default=Path("map.json"), help="Output JSON path")
    map_parser.add_argument("--only-extern-calls", action="store_true", help="Emit only external callsites in the map")
    map_parser.add_argument("--with-dwarf", action="store_true", help="Include DWARF file:line info where available")
    map_parser.add_argument("--bytes", action="store_true", help="Include instruction bytes for callsites")
    map_parser.add_argument("--analysis-level", choices=["symbols", "basic-blocks"], default="basic-blocks",
                            help="Granularity of control flow extraction")

    trace_parser = subparsers.add_parser("trace", help="Trace runtime activity of a process using map information")
    trace_parser.add_argument("--pid", type=int, help="PID of the process to attach to")
    trace_parser.add_argument("--spawn", type=Path, help="Binary to spawn under instrumentation")
    trace_parser.add_argument("--args", nargs=argparse.REMAINDER, help="Arguments for spawned binary")
    trace_parser.add_argument("--map", type=Path, required=True, help="Path to previously generated map.json")
    trace_parser.add_argument("--backend", choices=["frida", "bcc", "dyninst"], default="frida",
                              help="Dynamic tracing backend to use")
    trace_parser.add_argument("--lib", action="append", dest="libs", help="Library soname(s) to trace")
    trace_parser.add_argument("--fn", action="append", dest="functions", help="Specific function name(s) to trace")
    trace_parser.add_argument("--callsite", action="append", dest="callsites", help="Calls site addresses to trace")
    trace_parser.add_argument("--output", type=Path, help="Write JSONL trace to file instead of stdout")
    trace_parser.add_argument("--sample", type=str, help="Sampling spec like 1/100 to keep 1 in every 100 calls")
    trace_parser.add_argument("--since", type=float, help="Ignore events before this timestamp (seconds)")
    trace_parser.add_argument("--duration", type=float, help="Stop tracing after duration seconds")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "map":
        mapping = dynmap.generate_map(
            binary_path=args.binary,
            only_external_calls=args.only_extern_calls,
            include_dwarf=args.with_dwarf,
            include_bytes=args.bytes,
            analysis_level=args.analysis_level,
        )
        args.output.write_text(json.dumps(mapping, indent=2))
        print(f"[+] map written to {args.output}")
        return 0

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
        )
        return 0 if result else 1

    parser.error("unknown command")
    return 1


def main_map() -> int:
    return main(["map", *sys.argv[1:]])


def main_trace() -> int:
    return main(["trace", *sys.argv[1:]])


if __name__ == "__main__":
    sys.exit(main())
