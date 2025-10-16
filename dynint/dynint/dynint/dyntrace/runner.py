"""Dispatcher for dynamic tracing backends."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from . import frida_backend
from .. import mapfile


BACKENDS = {
    "frida": frida_backend.FridaBackend,
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
) -> bool:
    try:
        backend_cls = BACKENDS[backend]
    except KeyError as exc:  # pragma: no cover - defensive
        raise SystemExit(f"Unsupported backend: {backend}") from exc

    mapping = mapfile.MapData.load(map_path)

    tracer = backend_cls(
        mapping=mapping,
        libs=list(libs or []),
        functions=list(functions or []),
        callsites=list(callsites or []),
        output_path=output_path,
        sample=sample,
        since=since,
        duration=duration,
    )
    if pid is not None:
        tracer.attach(pid)
    elif spawn is not None:
        tracer.spawn(str(spawn), list(spawn_args or []))
    else:
        raise SystemExit("Either --pid or --spawn must be provided")
    return True
