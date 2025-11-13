"""Capstone-based disassembler backend."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Any

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

from . import DisassemblerBackend, AnalysisResult
from ..behavior_algebra import InstructionRecord

LOGGER = logging.getLogger(__name__)


class CapstoneBackend(DisassemblerBackend):
    """Enhanced Capstone disassembler backend with full instruction export."""
    
    def __init__(self, binary_path: Path):
        super().__init__(binary_path)
        self.cs = None
        self.instructions_cache: List[InstructionRecord] = []
        self._init_capstone()
    
    def _init_capstone(self) -> None:
        """Initialize Capstone engine."""
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.cs.detail = True
        except ImportError:
            raise RuntimeError("Capstone library not available")
    
    def disassemble(self) -> List[InstructionRecord]:
        """Extract instruction-level disassembly using Capstone."""
        if self.instructions_cache:
            return self.instructions_cache
        
        if not self.cs:
            return []
        
        instructions = []
        SHF_EXECINSTR = 0x4
        
        try:
            with self.binary_path.open("rb") as fp:
                elf = ELFFile(fp)
                
                for section in elf.iter_sections():
                    if not (section["sh_flags"] & SHF_EXECINSTR):
                        continue
                    
                    try:
                        data = section.data()
                        addr = section["sh_addr"]
                        
                        for insn in self.cs.disasm(data, addr):
                            record = InstructionRecord(
                                address=f"{insn.address:x}",
                                mnemonic=insn.mnemonic or "",
                                operands=insn.op_str or "",
                                bytes=insn.bytes.hex() if insn.bytes else "",
                                size=insn.size
                            )
                            instructions.append(record)
                    except Exception as e:
                        LOGGER.warning(f"Failed to disassemble section: {e}")
        except Exception as e:
            LOGGER.error(f"Failed to open binary: {e}")
            return []
        
        instructions.sort(key=lambda x: int(x.address, 16))
        self.instructions_cache = instructions
        return instructions
    
    def get_functions(self) -> List[Dict[str, Any]]:
        """Extract function metadata from symbol table."""
        functions = []
        
        try:
            with self.binary_path.open("rb") as fp:
                elf = ELFFile(fp)
                
                for section in elf.iter_sections():
                    if not isinstance(section, SymbolTableSection):
                        continue
                    
                    for symbol in section.iter_symbols():
                        if symbol["st_info"]["type"] != "STT_FUNC":
                            continue
                        addr = symbol["st_value"]
                        size = symbol["st_size"]
                        if addr == 0:
                            continue
                        
                        functions.append({
                            "name": symbol.name or f"func_{addr:x}",
                            "addr": f"0x{addr:x}",
                            "size": size,
                            "bind": symbol["st_info"]["bind"],
                            "section": str(symbol["st_shndx"]),
                            "blocks": []  # Will be computed by block analysis
                        })
        except Exception as e:
            LOGGER.warning(f"Failed to extract functions: {e}")
        
        return functions
    
    def get_plt_entries(self) -> Dict[str, str]:
        """Extract PLT entries."""
        plt_map = {}
        
        try:
            with self.binary_path.open("rb") as fp:
                elf = ELFFile(fp)
                
                for section in elf.iter_sections():
                    if not isinstance(section, RelocationSection):
                        continue
                    
                    try:
                        target_section = elf.get_section(section["sh_info"])
                        if not target_section or not target_section.name.startswith(".plt"):
                            continue
                        
                        entry_size = target_section["sh_entsize"] or 16
                        base_addr = target_section["sh_addr"]
                        skip = 1 if target_section.name == ".plt" else 0
                        
                        for idx, reloc in enumerate(section.iter_relocations()):
                            symbol = section.get_symbol(reloc.entry["r_info_sym"])
                            if not symbol or not symbol.name:
                                continue
                            plt_addr = base_addr + entry_size * (idx + skip)
                            plt_map[f"0x{plt_addr:x}"] = symbol.name
                    except Exception as e:
                        LOGGER.warning(f"Failed to extract PLT entries: {e}")
        except Exception as e:
            LOGGER.warning(f"Failed to open binary for PLT extraction: {e}")
        
        return plt_map
    
    def analyze(self) -> AnalysisResult:
        """Perform complete Capstone-based analysis."""
        instructions = self.disassemble()
        functions = self.get_functions()
        plt_entries = self.get_plt_entries()
        
        # Extract callsites from instructions
        callsites = []
        try:
            from capstone import CS_GRP_CALL
            if self.cs:
                with self.binary_path.open("rb") as fp:
                    elf = ELFFile(fp)
                    for insn_data in instructions:
                        addr_int = int(insn_data.address, 16)
                        # Re-decode to get groups info
                        for section in elf.iter_sections():
                            if section["sh_flags"] & 0x4:  # SHF_EXECINSTR
                                data = section.data()
                                section_addr = section["sh_addr"]
                                section_end = section_addr + section["sh_size"]
                                if section_addr <= addr_int < section_end:
                                    offset = addr_int - section_addr
                                    for insn in self.cs.disasm(data[offset:offset+16], addr_int):
                                        if CS_GRP_CALL in insn.groups:
                                            callsite = {
                                                "at_addr": f"0x{insn.address:x}",
                                                "type": "call",
                                                "target": insn.op_str or "unknown",
                                                "size": insn.size
                                            }
                                            callsites.append(callsite)
                                        break
                                    break
        except Exception as e:
            LOGGER.warning(f"Failed to extract callsites: {e}")
        
        return AnalysisResult(
            binary_metadata=self.get_binary_metadata(),
            functions=functions,
            instructions=instructions,
            callsites=callsites,
            libraries=[],  # Will be filled by main mapper
            plt_entries=plt_entries,
            cfg_data={},
            disassembler="capstone"
        )