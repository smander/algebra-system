"""Disassembler backends package for multi-engine binary analysis."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from ..behavior_algebra import InstructionRecord

LOGGER = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Unified result structure for all disassembler backends."""
    binary_metadata: Dict[str, Any]
    functions: List[Dict[str, Any]]
    instructions: List[InstructionRecord]
    callsites: List[Dict[str, Any]]
    libraries: List[Dict[str, Any]]
    plt_entries: Dict[str, str]
    cfg_data: Dict[str, Any]
    disassembler: str


class DisassemblerBackend(ABC):
    """Abstract base class for disassembler backends."""
    
    def __init__(self, binary_path: Path):
        self.binary_path = binary_path
        self.elf: Optional[ELFFile] = None
        self._load_elf()
    
    def _load_elf(self) -> None:
        """Load ELF file for metadata extraction."""
        # Don't load ELF here - it will be loaded when needed
        # to avoid file handle issues
        self.elf = None
    
    @abstractmethod
    def analyze(self) -> AnalysisResult:
        """Perform complete binary analysis."""
        pass
    
    @abstractmethod
    def disassemble(self) -> List[InstructionRecord]:
        """Extract instruction-level disassembly."""
        pass
    
    def get_binary_metadata(self) -> Dict[str, Any]:
        """Extract basic binary metadata."""
        try:
            with self.binary_path.open("rb") as fp:
                elf = ELFFile(fp)
                entry = elf.header["e_entry"]
                pie = elf.header["e_type"] == "ET_DYN"
                load_bases = [segment["p_vaddr"] for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]
                base = min(load_bases) if load_bases else 0
                
                return {
                    "path": str(self.binary_path.resolve()),
                    "pie": pie,
                    "image_base": base,
                    "entry": entry,
                }
        except Exception as e:
            LOGGER.warning(f"Failed to load ELF file: {e}")
            return {"path": str(self.binary_path), "pie": False, "image_base": 0, "entry": 0}


def create_backend(backend_type: str, binary_path: Path) -> DisassemblerBackend:
    """Factory function to create appropriate disassembler backend."""
    if backend_type == "capstone":
        from .capstone import CapstoneBackend
        return CapstoneBackend(binary_path)
    elif backend_type == "angr":
        from .angr import AngrBackend
        return AngrBackend(binary_path)
    elif backend_type == "objdump":
        from .objdump import ObjdumpBackend
        return ObjdumpBackend(binary_path)
    else:
        raise ValueError(f"Unknown backend type: {backend_type}")


def get_available_backends() -> List[str]:
    """Get list of available disassembler backends."""
    available = []
    
    # Test Capstone
    try:
        import capstone
        available.append("capstone")
    except ImportError:
        pass
    
    # Test Angr
    try:
        import angr
        available.append("angr")
    except ImportError:
        pass
    
    # Test objdump
    import subprocess
    try:
        subprocess.run(["objdump", "--version"], capture_output=True, check=True)
        available.append("objdump")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return available


# Supported backends list
SUPPORTED_BACKENDS = ["capstone", "angr", "objdump"]

# Export main classes and functions
__all__ = [
    "DisassemblerBackend", 
    "AnalysisResult", 
    "create_backend", 
    "get_available_backends",
    "SUPPORTED_BACKENDS"
]