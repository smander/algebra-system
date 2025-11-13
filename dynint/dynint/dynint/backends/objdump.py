"""Objdump-based disassembler backend for universal compatibility."""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any

from . import DisassemblerBackend, AnalysisResult
from ..behavior_algebra import InstructionRecord

LOGGER = logging.getLogger(__name__)


class ObjdumpBackend(DisassemblerBackend):
    """Objdump-based backend for universal compatibility."""
    
    def disassemble(self) -> List[InstructionRecord]:
        """Extract instruction-level disassembly using objdump."""
        instructions = []
        
        try:
            # Run objdump -d for disassembly
            result = subprocess.run(
                ["objdump", "-d", str(self.binary_path)],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse objdump output more robustly
            lines = result.stdout.split('\n')
            current_function = None
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Check for function headers like "0000000000401000 <main>:"
                if '<' in line and '>:' in line:
                    current_function = line
                    continue
                
                # Look for instruction lines
                # Format: "  401000:  48 89 d8                mov    %rbx,%rax"
                if ':' in line and (line[0].isspace() or line[0].isdigit() or line[0].lower() in 'abcdef'):
                    try:
                        # Split on colon first
                        addr_part, rest = line.split(':', 1)
                        addr_part = addr_part.strip()
                        
                        # Skip if not a valid hex address
                        if not addr_part or not all(c.isdigit() or c.lower() in 'abcdef' for c in addr_part):
                            continue
                        
                        # Parse the rest: bytes and instruction
                        rest = rest.strip()
                        
                        # Find where bytes end and instruction begins
                        # Look for multiple spaces or tab
                        parts = rest.split('\t') if '\t' in rest else rest.split('  ')
                        
                        if len(parts) >= 2:
                            bytes_part = parts[0].strip()
                            insn_part = ''.join(parts[1:]).strip()
                        else:
                            # Fallback: try to split on multiple spaces
                            split_parts = [p for p in rest.split(' ') if p]
                            if len(split_parts) >= 2:
                                # Assume first part is bytes, rest is instruction
                                bytes_part = split_parts[0]
                                insn_part = ' '.join(split_parts[1:])
                            else:
                                continue
                        
                        # Parse instruction mnemonic and operands
                        if ' ' in insn_part:
                            mnemonic, operands = insn_part.split(' ', 1)
                        else:
                            mnemonic = insn_part
                            operands = ""
                        
                        # Clean up operands (convert AT&T syntax to Intel-like)
                        operands = operands.replace('%', '').replace('$', '')
                        
                        # Create instruction record
                        addr = int(addr_part, 16)
                        clean_bytes = bytes_part.replace(' ', '')
                        
                        record = InstructionRecord(
                            address=f"{addr:x}",
                            mnemonic=mnemonic,
                            operands=operands,
                            bytes=clean_bytes,
                            size=len(clean_bytes) // 2 if clean_bytes else 1
                        )
                        instructions.append(record)
                        
                    except (ValueError, IndexError) as e:
                        LOGGER.debug(f"Failed to parse objdump line '{line}': {e}")
                        continue
        
        except subprocess.CalledProcessError as e:
            LOGGER.error(f"objdump failed: {e}")
        except FileNotFoundError:
            LOGGER.error("objdump not found in PATH")
        
        instructions.sort(key=lambda x: int(x.address, 16))
        return instructions
    
    def get_functions(self) -> List[Dict[str, Any]]:
        """Extract function information using objdump."""
        functions = []
        
        try:
            # Method 1: Try objdump -t (symbol table)
            result = subprocess.run(
                ["objdump", "-t", str(self.binary_path)],
                capture_output=True,
                text=True,
                check=False  # Don't fail if this doesn't work
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if ' F ' in line and ('.text' in line or 'CODE' in line):
                        parts = line.split()
                        if len(parts) >= 6:
                            addr_str = parts[0]
                            flags = parts[1] if len(parts) > 1 else ""
                            section = parts[2] if len(parts) > 2 else ""
                            size_str = parts[4] if len(parts) > 4 else "0"
                            name = parts[-1]
                            
                            try:
                                addr = int(addr_str, 16)
                                size = int(size_str, 16) if size_str != "0" and size_str.isdigit() else 0
                                
                                functions.append({
                                    "name": name,
                                    "addr": f"0x{addr:x}",
                                    "size": size,
                                    "bind": "STB_GLOBAL" if 'g' in flags else "STB_LOCAL",
                                    "section": section,
                                    "blocks": []
                                })
                            except ValueError:
                                continue
            
            # Method 2: Extract from disassembly output if symbol table failed
            if not functions:
                result = subprocess.run(
                    ["objdump", "-d", str(self.binary_path)],
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        # Look for function headers like "0000000000401000 <main>:"
                        if '<' in line and '>:' in line:
                            try:
                                addr_part = line.split(' ')[0]
                                name_part = line[line.find('<')+1:line.find('>')]
                                
                                addr = int(addr_part, 16)
                                
                                functions.append({
                                    "name": name_part,
                                    "addr": f"0x{addr:x}",
                                    "size": 0,  # Size unknown from disassembly
                                    "bind": "STB_GLOBAL",
                                    "section": "text",
                                    "blocks": []
                                })
                            except (ValueError, IndexError):
                                continue
        
        except subprocess.CalledProcessError as e:
            LOGGER.error(f"objdump failed: {e}")
        except FileNotFoundError:
            LOGGER.error("objdump not found in PATH")
        
        return functions
    
    def get_plt_entries(self) -> Dict[str, str]:
        """Extract PLT entries using objdump."""
        plt_entries = {}
        
        try:
            # Method 1: objdump -R for dynamic relocations
            result = subprocess.run(
                ["objdump", "-R", str(self.binary_path)],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if 'JUMP_SLOT' in line or 'JMP_SLOT' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            addr_str = parts[0]
                            symbol_name = parts[-1]
                            try:
                                addr = int(addr_str, 16)
                                plt_entries[f"0x{addr:x}"] = symbol_name
                            except ValueError:
                                continue
            
            # Method 2: objdump -t for PLT symbols
            result = subprocess.run(
                ["objdump", "-t", str(self.binary_path)],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '.plt' in line:
                        parts = line.split()
                        if len(parts) >= 6:
                            addr_str = parts[0]
                            name = parts[-1]
                            try:
                                addr = int(addr_str, 16)
                                # Remove @plt suffix if present
                                clean_name = name.replace('@plt', '')
                                plt_entries[f"0x{addr:x}"] = clean_name
                            except ValueError:
                                continue
        
        except subprocess.CalledProcessError as e:
            LOGGER.warning(f"objdump PLT extraction failed: {e}")
        except FileNotFoundError:
            LOGGER.warning("objdump not found in PATH")
        
        return plt_entries
    
    def analyze(self) -> AnalysisResult:
        """Perform complete objdump-based analysis."""
        instructions = self.disassemble()
        functions = self.get_functions()
        plt_entries = self.get_plt_entries()
        
        return AnalysisResult(
            binary_metadata=self.get_binary_metadata(),
            functions=functions,
            instructions=instructions,
            callsites=[],
            libraries=[],
            plt_entries=plt_entries,
            cfg_data={},
            disassembler="objdump"
        )