"""Address and mapping utilities shared between dynmap and dyntrace."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional


@dataclass
class ProcMapEntry:
    start: int
    end: int
    perms: str
    offset: int
    dev: str
    inode: int
    pathname: str | None

    @property
    def size(self) -> int:
        return self.end - self.start

    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.end


def parse_proc_maps(pid: int) -> List[ProcMapEntry]:
    """Parse `/proc/<pid>/maps` into a list of `ProcMapEntry` objects."""
    maps_path = Path(f"/proc/{pid}/maps")
    entries: List[ProcMapEntry] = []
    for line in maps_path.read_text().splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        addr_range, perms, offset, dev, inode, *rest = parts
        start_str, end_str = addr_range.split("-")
        pathname = rest[0] if rest else None
        entries.append(
            ProcMapEntry(
                start=int(start_str, 16),
                end=int(end_str, 16),
                perms=perms,
                offset=int(offset, 16),
                dev=dev,
                inode=int(inode),
                pathname=pathname,
            )
        )
    return entries


def find_module_base(pid: int, soname: str) -> Optional[ProcMapEntry]:
    """Return the first executable mapping whose path contains the provided soname."""
    for entry in parse_proc_maps(pid):
        if entry.pathname and soname in entry.pathname:
            if "x" in entry.perms:
                return entry
    return None


def rebase_addr(static_addr: int, static_base: int, runtime_base: int) -> int:
    """Translate a static address (from the ELF image) into its runtime value."""
    return static_addr - static_base + runtime_base


def iter_module_bases(maps: Iterable[ProcMapEntry], soname: str) -> Iterator[ProcMapEntry]:
    """Yield all mappings that match a given shared-object name."""
    for entry in maps:
        if entry.pathname and soname in entry.pathname and "x" in entry.perms:
            yield entry


def normalize_path(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    try:
        return str(Path(path))
    except Exception:  # pragma: no cover - best effort normalisation
        return path
