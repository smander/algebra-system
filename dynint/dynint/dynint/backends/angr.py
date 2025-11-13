"""Angr-based disassembler backend for advanced binary analysis."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Any

from . import DisassemblerBackend, AnalysisResult
from ..behavior_algebra import InstructionRecord

LOGGER = logging.getLogger(__name__)


class AngrBackend(DisassemblerBackend):
    """Angr-based backend for advanced binary analysis."""
    
    def __init__(self, binary_path: Path):
        super().__init__(binary_path)
        self.project = None
        self._init_angr()
    
    def _init_angr(self) -> None:
        """Initialize Angr project."""
        try:
            import angr
            self.project = angr.Project(str(self.binary_path), load_options={'auto_load_libs': False})
        except ImportError:
            raise RuntimeError("Angr library not available")
        except Exception as e:
            raise RuntimeError(f"Failed to load binary with Angr: {e}")
    
    def disassemble(self) -> List[InstructionRecord]:
        """Extract instruction-level disassembly using Angr."""
        if not self.project:
            return []
        
        instructions = []
        
        try:
            # Get all executable sections and disassemble them
            for section in self.project.loader.main_object.sections:
                if section.is_executable and section.memsize > 0:
                    start_addr = section.vaddr
                    end_addr = start_addr + section.memsize
                    
                    # Disassemble section in chunks to avoid memory issues
                    current_addr = start_addr
                    while current_addr < end_addr:
                        try:
                            # Create a block starting at current address
                            block = self.project.factory.block(current_addr, opt_level=0)
                            
                            for insn in block.disassembly.insns:
                                # Extract operands more carefully
                                operands_str = ""
                                try:
                                    if hasattr(insn, 'op_str'):
                                        operands_str = insn.op_str
                                    elif hasattr(insn, 'operands'):
                                        operands_str = " ".join(str(op) for op in insn.operands)
                                except Exception:
                                    operands_str = ""
                                
                                # Extract bytes more safely
                                bytes_str = ""
                                try:
                                    if hasattr(insn, 'bytes'):
                                        bytes_str = "".join(f"{b:02x}" for b in insn.bytes)
                                    else:
                                        bytes_str = ""
                                except Exception:
                                    bytes_str = ""
                                
                                record = InstructionRecord(
                                    address=f"{insn.address:x}",
                                    mnemonic=insn.mnemonic or "unknown",
                                    operands=operands_str,
                                    bytes=bytes_str,
                                    size=getattr(insn, 'size', len(insn.bytes) if hasattr(insn, 'bytes') else 0)
                                )
                                instructions.append(record)
                            
                            # Move to next block
                            current_addr = block.addr + block.size
                            
                        except Exception as e:
                            LOGGER.debug(f"Failed to disassemble block at {current_addr:x}: {e}")
                            current_addr += 1  # Skip problematic byte
                            continue
                            
        except Exception as e:
            LOGGER.warning(f"Angr disassembly failed: {e}")
        
        # Remove duplicates and sort
        seen_addresses = set()
        unique_instructions = []
        for instr in instructions:
            if instr.address not in seen_addresses:
                seen_addresses.add(instr.address)
                unique_instructions.append(instr)
        
        unique_instructions.sort(key=lambda x: int(x.address, 16))
        return unique_instructions
    
    def get_functions(self) -> List[Dict[str, Any]]:
        """Extract function information using Angr's CFG."""
        if not self.project:
            return []
        
        functions = []
        
        try:
            # Generate CFG with conservative settings
            cfg = self.project.analyses.CFGFast(normalize=True, force_complete_scan=False)
            
            for func_addr, func in cfg.functions.items():
                # Include all functions, not just named ones
                func_name = func.name if func.name else f"sub_{func_addr:x}"
                
                # Skip very small functions that might be artifacts
                if func.size < 1:
                    continue
                    
                # Get basic block addresses
                block_addrs = []
                try:
                    block_addrs = [f"0x{block.addr:x}" for block in func.blocks if hasattr(block, 'addr')]
                except Exception:
                    block_addrs = []
                
                functions.append({
                    "name": func_name,
                    "addr": f"0x{func_addr:x}",
                    "size": func.size,
                    "bind": "STB_GLOBAL" if getattr(func, 'is_plt', False) else "STB_LOCAL",
                    "section": "unknown",
                    "blocks": block_addrs,
                    "is_plt": getattr(func, 'is_plt', False)
                })
        except Exception as e:
            LOGGER.warning(f"Angr CFG analysis failed: {e}")
        
        return functions
    
    def get_plt_entries(self) -> Dict[str, str]:
        """Extract PLT entries using Angr."""
        if not self.project:
            return {}
        
        plt_entries = {}
        
        try:
            # Try multiple methods to extract PLT entries
            main_obj = self.project.loader.main_object
            
            # Method 1: Direct PLT access
            if hasattr(main_obj, 'plt') and main_obj.plt:
                for symbol_name, symbol in main_obj.plt.items():
                    if hasattr(symbol, 'rebased_addr'):
                        plt_entries[f"0x{symbol.rebased_addr:x}"] = symbol_name
                    elif hasattr(symbol, 'addr'):
                        plt_entries[f"0x{symbol.addr:x}"] = symbol_name
            
            # Method 2: Symbol table PLT entries
            if hasattr(main_obj, 'symbols'):
                for symbol in main_obj.symbols:
                    if symbol.is_function and '@plt' in symbol.name:
                        base_name = symbol.name.replace('@plt', '')
                        plt_entries[f"0x{symbol.rebased_addr:x}"] = base_name
            
            # Method 3: Relocation entries
            if hasattr(main_obj, 'relocs'):
                for reloc in main_obj.relocs:
                    if hasattr(reloc, 'symbol') and reloc.symbol:
                        symbol_name = reloc.symbol.name
                        if symbol_name:
                            plt_entries[f"0x{reloc.rebased_addr:x}"] = symbol_name
                            
        except Exception as e:
            LOGGER.warning(f"Angr PLT extraction failed: {e}")
        
        return plt_entries
    
    def analyze(self) -> AnalysisResult:
        """Perform complete Angr-based analysis."""
        instructions = self.disassemble()
        functions = self.get_functions()
        plt_entries = self.get_plt_entries()
        
        # Extract callsites using Angr's analysis
        callsites = []
        try:
            cfg = self.project.analyses.CFGFast(normalize=True, force_complete_scan=False)
            
            for func in cfg.functions.values():
                try:
                    # Get call sites within this function
                    if hasattr(func, 'get_call_sites'):
                        for callsite in func.get_call_sites():
                            callsites.append({
                                "at_addr": f"0x{callsite:x}",
                                "type": "call",
                                "target": "unknown",
                                "size": 5  # Typical x86-64 call size
                            })
                    
                    # Alternative: analyze blocks for call instructions
                    for block in func.blocks:
                        try:
                            # Check if block has call instructions
                            block_obj = self.project.factory.block(block.addr, opt_level=0)
                            for insn in block_obj.disassembly.insns:
                                if 'call' in insn.mnemonic.lower():
                                    callsites.append({
                                        "at_addr": f"0x{insn.address:x}",
                                        "type": "call",
                                        "target": getattr(insn, 'op_str', 'unknown'),
                                        "size": getattr(insn, 'size', 5)
                                    })
                        except Exception:
                            continue
                            
                except Exception as e:
                    LOGGER.debug(f"Failed to analyze function {func.addr:x}: {e}")
                    continue
                    
        except Exception as e:
            LOGGER.warning(f"Angr callsite analysis failed: {e}")
        
        return AnalysisResult(
            binary_metadata=self.get_binary_metadata(),
            functions=functions,
            instructions=instructions,
            callsites=callsites,
            libraries=[],
            plt_entries=plt_entries,
            cfg_data={},
            disassembler="angr"
        )