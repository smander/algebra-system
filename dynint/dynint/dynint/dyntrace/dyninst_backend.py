"""Real DynInst-based dynamic tracer backend."""
from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .. import mapfile

LOGGER = logging.getLogger(__name__)


class DynInstBackend:
    """Real DynInst backend using native wrapper only."""

    def __init__(
        self,
        mapping: mapfile.MapData,
        libs: List[str],
        functions: List[str],
        callsites: List[str],
        output_path: Optional[Path],
        sample: Optional[str],
        since: Optional[float],
        duration: Optional[float],
        instruction_level: bool = False,
        memory_access: bool = False,
        control_flow: bool = False,
        vulnerability_focus: Optional[str] = None,
    ) -> None:
        self.mapping = mapping
        self.requested_libs = libs or []
        self.requested_functions = functions or []
        self.requested_callsites = callsites or []
        self.output_path = output_path
        self.sample_spec = sample
        self.since = since
        self.duration = duration
        self.instruction_level = instruction_level
        self.memory_access = memory_access
        self.control_flow = control_flow
        self.vulnerability_focus = vulnerability_focus

        self._wrapper_path = self._locate_wrapper()
        self._temp_output: Optional[Path] = None

        if not self._wrapper_path:
            raise RuntimeError(
                "DynInst wrapper not found. Please build the dyninst_wrapper executable."
            )

    def attach(self, pid: int) -> None:
        """Attach to an already running process."""
        self._run_wrapper("attach", str(pid), [])

    def spawn(self, binary: str, argv: List[str]) -> None:
        """Spawn a binary under instrumentation."""
        self._run_wrapper("spawn", binary, argv)

    def _locate_wrapper(self) -> Optional[str]:
        """Find the dyninst_wrapper executable on disk."""
        candidates: Iterable[Path] = []
        env_value = os.environ.get("DYNINST_WRAPPER")
        if env_value:
            candidates = [Path(env_value)]
        else:
            repo_root = Path(__file__).resolve().parents[2]
            candidates = [
                Path("/usr/local/bin/dyninst_wrapper"),
                repo_root / "dyninst_wrapper",
                repo_root / "build" / "dyninst_wrapper",
                Path("/opt/dyninst/bin/dyninst_wrapper"),
                Path("/workspace/dyninst_wrapper"),  # Docker path
            ]
        for candidate in candidates:
            if candidate and candidate.exists() and os.access(candidate, os.X_OK):
                return str(candidate)
        return None

    def _prepare_output(self) -> Optional[Path]:
        if self.output_path:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            return self.output_path
        fd, tmp_path = tempfile.mkstemp(prefix="dyninst_trace_", suffix=".jsonl")
        os.close(fd)
        self._temp_output = Path(tmp_path)
        return self._temp_output

    def _cleanup_temp_output(self) -> None:
        if self._temp_output and self._temp_output.exists():
            try:
                self._temp_output.unlink()
            except OSError:
                LOGGER.debug("Failed to remove temporary output %s", self._temp_output)
        self._temp_output = None

    def _stream_temp_output(self) -> None:
        if self.output_path or not self._temp_output:
            return
        try:
            with self._temp_output.open("r", encoding="utf-8") as handle:
                for line in handle:
                    sys.stdout.write(line)
        finally:
            self._cleanup_temp_output()

    def _run_wrapper(self, mode: str, target: str, spawn_args: List[str]) -> None:
        output_path = self._prepare_output()
        cmd: List[str] = [self._wrapper_path or "dyninst_wrapper", mode, target]
        if spawn_args:
            cmd.extend(spawn_args)
        if output_path:
            cmd.extend(["--output", str(output_path)])
        if self.duration:
            cmd.extend(["--duration", str(self.duration)])
        if self.requested_functions:
            cmd.extend(["--functions", ",".join(self.requested_functions)])

        LOGGER.info(
            "Invoking DynInst wrapper: %s",
            " ".join(shlex.quote(part) for part in cmd),
        )

        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            LOGGER.error("DynInst wrapper missing: %s", exc)
            self._cleanup_temp_output()
            raise RuntimeError(f"DynInst wrapper not found: {exc}")
        except subprocess.CalledProcessError as exc:
            LOGGER.error("DynInst wrapper failed with exit code %s", exc.returncode)
            if exc.stdout:
                LOGGER.error("wrapper stdout:%s%s", os.linesep, exc.stdout.strip())
            if exc.stderr:
                LOGGER.error("wrapper stderr:%s%s", os.linesep, exc.stderr.strip())
            self._cleanup_temp_output()
            raise RuntimeError(f"DynInst wrapper failed: {exc}")
        except subprocess.TimeoutExpired as exc:
            LOGGER.error("DynInst wrapper timed out: %s", exc)
            self._cleanup_temp_output()
            raise RuntimeError(f"DynInst wrapper timed out: {exc}")

        if result.stdout:
            LOGGER.debug("Wrapper stdout:%s%s", os.linesep, result.stdout.strip())
        if result.stderr:
            LOGGER.debug("Wrapper stderr:%s%s", os.linesep, result.stderr.strip())

        self._stream_temp_output()