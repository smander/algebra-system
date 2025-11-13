"""Dispatcher for dynamic tracing backends."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from . import dyninst_backend
from .. import mapfile


BACKENDS = {
    "dyninst": dyninst_backend.DynInstBackend,  # DynInst backend (simulation for testing)
    # Future backends can be added here.
}


def run_trace(
    backend: str,
    map_path: Path,
    pid: Optional[int] = None,
    spawn: Optional[Path] = None,
    spawn_args: Optional[Iterable[str]] = None,
    libs: Optional[Iterable[str]] = None,
    functions: Optional[Iterable[str]] = None,
    callsites: Optional[Iterable[str]] = None,
    output_path: Optional[Path] = None,
    sample: Optional[str] = None,
    since: Optional[float] = None,
    duration: Optional[float] = None,
    # DynInst-specific options
    instruction_level: bool = False,
    memory_access: bool = False,
    control_flow: bool = False,
    vulnerability_focus: Optional[str] = None,
) -> bool:
    try:
        backend_cls = BACKENDS[backend]
    except KeyError as exc:  # pragma: no cover - defensive
        raise SystemExit(f"Unsupported backend: {backend}") from exc

    mapping = mapfile.MapData.load(map_path)

    # Create tracer with DynInst options
    tracer = backend_cls(
        mapping=mapping,
        libs=list(libs or []),
        functions=list(functions or []),
        callsites=list(callsites or []),
        output_path=output_path,
        sample=sample,
        since=since,
        duration=duration,
        instruction_level=instruction_level,
        memory_access=memory_access,
        control_flow=control_flow,
        vulnerability_focus=vulnerability_focus,
    )
    if pid is not None:
        tracer.attach(pid)
    elif spawn is not None:
        tracer.spawn(str(spawn), list(spawn_args or []))
    else:
        raise SystemExit("Either --pid or --spawn must be provided")
    return True
