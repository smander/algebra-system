"""Frida-based dynamic tracer backend."""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import frida

from .sampling import SamplerFactory
from .. import addrutils, mapfile


class FridaBackend:
    """Implements the dynamic tracer using Frida."""

    def __init__(
        self,
        mapping: mapfile.MapData,
        libs: Iterable[str],
        functions: Iterable[str],
        callsites: Iterable[str],
        output_path: Optional[Path],
        sample: Optional[str],
        since: Optional[float],
        duration: Optional[float],
    ) -> None:
        self.mapping = mapping
        self.requested_libs = [normalize_soname(lib) for lib in libs]
        self.requested_functions = set(functions or [])
        self.requested_callsites = {
            parse_address(value)
            for value in (callsites or [])
        }
        self.output_path = output_path
        self.sample_spec = sample
        self.since = since
        self.duration = duration

        self._session: Optional[frida.core.Session] = None
        self._script: Optional[frida.core.Script] = None
        self._pid: Optional[int] = None
        self._stop_event = threading.Event()
        self._sampler = SamplerFactory.from_spec(sample)
        self._writer, self._outfile = self._make_writer()

        self.target_libs = self._select_libs()
        self.target_functions = self._select_functions()
        self.function_names = {item["symbol"] for item in self.target_functions}
        self.callsite_records = self._select_callsites()
        self.return_lookup = self._build_return_lookup()

        self._proc_maps: List[addrutils.ProcMapEntry] = []
        self._main_map: Optional[addrutils.ProcMapEntry] = None
        self._runtime_callsites: List[Dict[str, object]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def attach(self, pid: int) -> None:
        self._pid = pid
        self._session = frida.attach(pid)
        self._run()

    def spawn(self, binary: str, argv: List[str]) -> None:
        pid = frida.spawn([binary, *argv])
        self._pid = pid
        self._session = frida.attach(pid)
        frida.resume(pid)
        self._run()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _select_libs(self) -> List[str]:
        if self.requested_libs:
            return [lib for lib in self.requested_libs if lib]
        return [normalize_soname(soname) for soname in self.mapping.iter_lib_sonames() if soname]

    def _select_functions(self) -> List[Dict[str, str]]:
        if self.requested_functions:
            hooks: List[Dict[str, Optional[str]]] = []
            for name in sorted(self.requested_functions):
                lib = None
                symbol = name
                if ":" in name:
                    lib, symbol = name.split(":", 1)
                    lib = normalize_soname(lib)
                hooks.append({"symbol": symbol, "library": lib, "qualified": None})
            return hooks
        symbols = {}
        for cs in self.mapping.callsites:
            if cs.call_type != "plt" or not isinstance(cs.target, str):
                continue
            symbols.setdefault(cs.target, {"symbol": cs.target, "library": None, "qualified": None})
        for vers in self.mapping.symbol_versions:
            if vers.symbol not in symbols:
                continue
            if vers.library and vers.library in self.target_libs:
                symbols[vers.symbol]["library"] = vers.library
                symbols[vers.symbol]["qualified"] = vers.qualified
        return list(symbols.values())

    def _select_callsites(self) -> Dict[int, mapfile.CallSite]:
        callsites: Dict[int, mapfile.CallSite] = {}
        use_filter = bool(self.requested_callsites)
        for cs in self.mapping.callsites:
            if cs.call_type != "plt":
                continue
            if use_filter and cs.at_addr not in self.requested_callsites:
                continue
            if self.function_names and isinstance(cs.target, str):
                if cs.target not in self.function_names:
                    continue
            callsites[cs.at_addr] = cs
        return callsites

    def _build_return_lookup(self) -> Dict[int, mapfile.CallSite]:
        lookup: Dict[int, mapfile.CallSite] = {}
        for addr, cs in self.callsite_records.items():
            size = cs.size or 0
            if size <= 0:
                continue
            lookup[addr + size] = cs
        return lookup

    def _prepare_runtime_context(self) -> None:
        if self._pid is None:
            raise RuntimeError("PID not set")
        self._proc_maps = addrutils.parse_proc_maps(self._pid)
        self._main_map = self._find_main_mapping()
        self._runtime_callsites = []
        if not self._main_map:
            return
        static_base = self.mapping.binary.base
        runtime_base = self._main_map.start
        for static_addr, cs in self.callsite_records.items():
            runtime_addr = addrutils.rebase_addr(static_addr, static_base, runtime_base)
            self._runtime_callsites.append(
                {
                    "runtime": hex(runtime_addr),
                    "static": hex(static_addr),
                    "size": cs.size,
                    "target": cs.target,
                }
            )

    def _find_main_mapping(self) -> Optional[addrutils.ProcMapEntry]:
        binary_path = Path(self.mapping.binary.path)
        for entry in self._proc_maps:
            if not entry.pathname:
                continue
            try:
                path = Path(entry.pathname)
            except Exception:
                continue
            if path.samefile(binary_path):
                return entry
        # Fallback: first executable mapping in process image
        for entry in self._proc_maps:
            if entry.pathname and "(deleted)" in entry.pathname:
                continue
            if "r-x" in entry.perms and entry.pathname and entry.pathname.endswith(binary_path.name):
                return entry
        return None

    def _make_writer(self):
        if self.output_path:
            outfile = self.output_path.open("w", encoding="utf-8")
            lock = threading.Lock()

            def _write(payload: Dict[str, object]) -> None:
                with lock:
                    outfile.write(json.dumps(payload) + "\n")
                    outfile.flush()

            return _write, outfile

        lock = threading.Lock()

        def _write(payload: Dict[str, object]) -> None:
            with lock:
                print(json.dumps(payload), file=sys.stdout, flush=True)

        return _write, None

    def _static_from_runtime(self, addr: int) -> Optional[int]:
        if not self._main_map:
            return None
        if not self._main_map.contains(addr):
            return None
        runtime_base = self._main_map.start
        static_base = self.mapping.binary.base
        return addr - runtime_base + static_base

    def _map_callsite(self, runtime_return: int) -> Optional[Dict[str, object]]:
        static_ret = self._static_from_runtime(runtime_return)
        if static_ret is None:
            return None
        callsite = self.return_lookup.get(static_ret)
        if not callsite:
            return None
        function = self.mapping.find_function_by_addr(callsite.at_addr)
        return {
            "callsite": hex(callsite.at_addr),
            "function": function.name if function else None,
            "file": callsite.file,
            "line": callsite.line,
            "target": callsite.target,
        }

    def _build_script_config(self) -> Dict[str, object]:
        function_hooks: List[Dict[str, Optional[str]]] = []
        for item in self.target_functions:
            function_hooks.append(
                {
                    "symbol": item["symbol"],
                    "library": item.get("library"),
                    "qualified": item.get("qualified"),
                }
            )
        config = {
            "libs": self.target_libs,
            "function_hooks": function_hooks,
            "callsites": self._runtime_callsites,
            "options": {
                "arg_count": 6,
            },
        }
        return config

    def _run(self) -> None:
        if not self._session:
            raise RuntimeError("Frida session not established")
        self._prepare_runtime_context()
        script_src = self._build_script()
        self._script = self._session.create_script(script_src)
        self._script.on("message", self._on_message)
        self._script.load()
        if self.duration:
            timer = threading.Timer(self.duration, self.stop)
            timer.start()
        try:
            while not self._stop_event.is_set():
                time.sleep(0.1)
        finally:
            self.stop()

    def stop(self) -> None:
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        if self._script:
            self._script.unload()
        if self._session:
            try:
                self._session.detach()
            except frida.InvalidOperationError:  # pragma: no cover - already detached
                pass
        if self._outfile:
            self._outfile.close()

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------
    def _on_message(self, message: Dict[str, object], data: bytes) -> None:  # pragma: no cover - live use
        mtype = message.get("type")
        if mtype == "send":
            payload = message.get("payload", {})
            kind = payload.get("kind")
            if kind == "function":
                self._enrich_function_event(payload)
            elif kind == "callsite":
                self._enrich_callsite_event(payload)
            self._emit_event(payload)
        elif mtype == "error":
            print(f"[frida:error] {message}", file=sys.stderr)

    def _emit_event(self, payload: Dict[str, object]) -> None:
        payload.setdefault("ts", time.time())
        if self.since and payload["ts"] < self.since:
            return
        if self._sampler and not self._sampler.allow():
            return
        self._writer(payload)

    def _enrich_function_event(self, payload: Dict[str, object]) -> None:
        ret_addr = payload.get("returnAddress")
        if ret_addr:
            try:
                runtime_return = int(ret_addr, 16)
            except (TypeError, ValueError):
                runtime_return = None
            if runtime_return:
                callsite = self._map_callsite(runtime_return)
                if callsite:
                    payload["callsite"] = callsite
        payload.setdefault("pid", self._pid)

    def _enrich_callsite_event(self, payload: Dict[str, object]) -> None:
        payload.setdefault("pid", self._pid)

    # ------------------------------------------------------------------
    # Script
    # ------------------------------------------------------------------
    def _build_script(self) -> str:
        config = self._build_script_config()
        return _FRIDA_TEMPLATE.replace("__CONFIG__", json.dumps(config))


def normalize_soname(value: Optional[str]) -> str:
    if not value:
        return ""
    return value.split("/")[-1]


def parse_address(value: str) -> int:
    value = value.strip()
    if value.startswith("0x"):
        return int(value, 16)
    return int(value, 10)


_FRIDA_TEMPLATE = r"""
const config = __CONFIG__;
const tracedFunctions = new Map();
const tracedCallsites = new Map();

function shouldTraceModule(moduleName) {
    if (!config.libs || config.libs.length === 0) {
        return true;
    }
    for (const name of config.libs) {
        if (!name) {
            continue;
        }
        if (moduleName.indexOf(name) !== -1) {
            return true;
        }
    }
    return false;
}

function hookModules() {
    Process.enumerateModules().forEach(module => {
        if (!shouldTraceModule(module.name)) {
            return;
        }
        hookFunctionsInModule(module);
    });
}

function hookFunctionsInModule(module) {
    (config.function_hooks || []).forEach(fn => {
        if (!fn.symbol) {
            return;
        }
        if (fn.library && module.name.indexOf(fn.library) === -1) {
            return;
        }
        const identifier = fn.symbol + "@" + module.name;
        if (tracedFunctions.has(identifier)) {
            return;
        }
        let address = null;
        try {
            address = Module.findExportByName(module.name, fn.symbol);
        } catch (err) {
            address = null;
        }
        if (address === null) {
            return;
        }
        installFunctionHook(identifier, module, fn.symbol, address);
    });
}

function installFunctionHook(identifier, module, symbol, address) {
    try {
        Interceptor.attach(address, {
            onEnter(args) {
                this.ts = Date.now() / 1000.0;
                this.retaddr = this.context.lr || this.context.rip;
                this.argsSnapshot = [];
                const argCount = (config.options && config.options.arg_count) || 6;
                for (let i = 0; i < argCount; i++) {
                    try {
                        this.argsSnapshot.push(args[i] ? args[i].toString() : null);
                    } catch (err) {
                        this.argsSnapshot.push(null);
                    }
                }
                this.threadId = Process.getCurrentThreadId();
            },
            onLeave(retval) {
                const payload = {
                    kind: "function",
                    function: symbol,
                    library: module.name,
                    args: this.argsSnapshot,
                    ret: retval ? retval.toString() : null,
                    returnAddress: this.retaddr ? this.retaddr.toString() : null,
                    duration: this.ts ? (Date.now() / 1000.0 - this.ts) : null,
                    tid: this.threadId,
                };
                send(payload);
            }
        });
        tracedFunctions.set(identifier, address);
    } catch (err) {
        send({kind: "log", level: "warn", message: "Failed to hook " + symbol + "@" + module.name, error: err.toString()});
    }
}

function installCallsiteHooks() {
    (config.callsites || []).forEach(cs => {
        if (!cs.runtime) {
            return;
        }
        const key = cs.runtime;
        if (tracedCallsites.has(key)) {
            return;
        }
        try {
            const ptrValue = ptr(cs.runtime);
            Interceptor.attach(ptrValue, {
                onEnter(args) {
                    const payload = {
                        kind: "callsite",
                        runtime: cs.runtime,
                        static: cs.static,
                        target: cs.target,
                        size: cs.size,
                        tid: Process.getCurrentThreadId(),
                        returnAddress: (this.context.lr || this.context.rip).toString(),
                    };
                    send(payload);
                }
            });
            tracedCallsites.set(key, ptrValue);
        } catch (err) {
            send({kind: "log", level: "warn", message: "Failed to hook callsite " + cs.runtime, error: err.toString()});
        }
    });
}

function hookDlopen() {
    const resolver = new ApiResolver('module');
    const patterns = ['*dlopen*', '*__libc_dlopen_mode'];
    patterns.forEach(pattern => {
        resolver.enumerateMatches(pattern).forEach(match => {
            Interceptor.attach(match.address, {
                onLeave(retval) {
                    setTimeout(hookModules, 10);
                }
            });
        });
    });
}

hookModules();
installCallsiteHooks();
hookDlopen();
"""
