"""Helpers for map.json parsing and validation."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class BasicBlock:
    addr: int
    size: int
    successors: List[int] = field(default_factory=list)


@dataclass
class CallSite:
    at_addr: int
    call_type: str
    target: str | int | None
    target_addr: int | None = None
    plt_addr: int | None = None
    size: int | None = None
    bytes: str | None = None
    file: str | None = None
    line: int | None = None


@dataclass
class FunctionEntry:
    name: str | None
    addr: int
    size: int
    blocks: List[BasicBlock] = field(default_factory=list)
    bind: str | None = None
    section: str | None = None


@dataclass
class LibraryEntry:
    soname: str
    needed: bool = True
    path: str | None = None
    versions: Dict[str, str] | None = None


@dataclass
class MapBinary:
    path: str
    pie: bool
    base: int
    entry: int


@dataclass
class SymbolVersion:
    symbol: str
    version: str
    qualified: str
    library: str | None = None


@dataclass
class MapData:
    binary: MapBinary
    functions: List[FunctionEntry]
    callsites: List[CallSite]
    libraries: List[LibraryEntry]
    symbol_versions: List[SymbolVersion] = field(default_factory=list)

    @classmethod
    def from_json(cls, payload: Dict[str, Any]) -> "MapData":
        binary = payload.get("binary") or {}
        fn_entries = []
        for item in payload.get("functions", []):
            blocks_payload = item.get("blocks", [])
            blocks: List[BasicBlock] = []
            for block in blocks_payload:
                if isinstance(block, dict):
                    addr_val = block.get("addr")
                    size_val = block.get("size", 0)
                    succ_val = block.get("successors", [])
                    blocks.append(
                        BasicBlock(
                            addr=int(addr_val, 16) if isinstance(addr_val, str) else int(addr_val or 0),
                            size=int(size_val),
                            successors=[
                                int(s, 16) if isinstance(s, str) else int(s)
                                for s in succ_val
                            ],
                        )
                    )
                else:
                    addr_int = int(block, 16) if isinstance(block, str) else int(block)
                    blocks.append(BasicBlock(addr=addr_int, size=0, successors=[]))
            fn_entries.append(
                FunctionEntry(
                    name=item.get("name"),
                    addr=int(item["addr"], 16) if isinstance(item.get("addr"), str) else int(item.get("addr", 0)),
                    size=int(item.get("size", 0)),
                    blocks=blocks,
                    bind=item.get("bind"),
                    section=item.get("section"),
                )
            )
        call_entries = [
            CallSite(
                at_addr=int(item["at_addr"], 16) if isinstance(item.get("at_addr"), str) else int(item.get("at_addr", 0)),
                call_type=item.get("type", "unknown"),
                target=item.get("target"),
                target_addr=(
                    int(item["target_addr"], 16)
                    if isinstance(item.get("target_addr"), str)
                    else (int(item["target_addr"]) if item.get("target_addr") is not None else None)
                ),
                plt_addr=(
                    int(item["plt_addr"], 16)
                    if isinstance(item.get("plt_addr"), str)
                    else (int(item["plt_addr"]) if item.get("plt_addr") is not None else None)
                ),
                size=int(item.get("size", 0)) or None,
                bytes=item.get("bytes"),
                file=item.get("file"),
                line=item.get("line"),
            )
            for item in payload.get("callsites", [])
        ]
        libs = [
            LibraryEntry(
                soname=item.get("soname") or item.get("name") or "",
                needed=item.get("needed", True),
                path=item.get("path"),
                versions=item.get("versions"),
            )
            for item in payload.get("libraries", [])
        ]
        symbol_versions_payload = payload.get("symbol_versions", [])
        symbol_versions = [
            SymbolVersion(
                symbol=item.get("symbol", ""),
                version=item.get("version", ""),
                qualified=item.get("qualified", ""),
                library=item.get("library"),
            )
            for item in symbol_versions_payload
            if item
        ]

        return cls(
            binary=MapBinary(
                path=binary.get("path", ""),
                pie=bool(binary.get("pie", False)),
                base=int(binary.get("image_base", binary.get("base", 0))),
                entry=int(binary.get("entry", 0)),
            ),
            functions=fn_entries,
            callsites=call_entries,
            libraries=libs,
            symbol_versions=symbol_versions,
        )

    @classmethod
    def load(cls, path: Path) -> "MapData":
        import json

        payload = json.loads(path.read_text())
        return cls.from_json(payload)

    def find_function_by_addr(self, addr: int) -> Optional[FunctionEntry]:
        for fn in self.functions:
            if fn.addr <= addr < fn.addr + max(fn.size, 1):
                return fn
        return None

    def to_json(self) -> Dict[str, Any]:
        return {
            "binary": {
                "path": self.binary.path,
                "pie": self.binary.pie,
                "image_base": self.binary.base,
                "entry": self.binary.entry,
            },
            "functions": [
                {
                    "name": fn.name,
                    "addr": hex(fn.addr),
                    "size": fn.size,
                    "blocks": [
                        {
                            "addr": hex(block.addr),
                            "size": block.size,
                            "successors": [hex(succ) for succ in block.successors],
                        }
                        for block in fn.blocks
                    ],
                    "bind": fn.bind,
                    "section": fn.section,
                }
                for fn in self.functions
            ],
            "callsites": [
                {
                    "at_addr": hex(cs.at_addr),
                    "type": cs.call_type,
                    "target": cs.target,
                    "target_addr": hex(cs.target_addr) if cs.target_addr is not None else None,
                    "plt_addr": hex(cs.plt_addr) if cs.plt_addr is not None else None,
                    "size": cs.size,
                    "bytes": cs.bytes,
                    "file": cs.file,
                    "line": cs.line,
                }
                for cs in self.callsites
            ],
            "libraries": [
                {
                    "soname": lib.soname,
                    "needed": lib.needed,
                    "path": lib.path,
                    "versions": lib.versions,
                }
                for lib in self.libraries
            ],
            "symbol_versions": [
                {
                    "symbol": sv.symbol,
                    "version": sv.version,
                    "qualified": sv.qualified,
                    "library": sv.library,
                }
                for sv in self.symbol_versions
            ],
        }

    def iter_lib_sonames(self) -> Iterable[str]:
        for lib in self.libraries:
            yield lib.soname
