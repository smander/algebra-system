"""Static mapping utilities for ELF binaries with multi-disassembler support."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

from .backends import create_backend, AnalysisResult, get_available_backends, SUPPORTED_BACKENDS
from .behavior_algebra import build_behavior_algebra, InstructionRecord

LOGGER = logging.getLogger(__name__)

# ELF flag for executable section contents
SHF_EXECINSTR = 0x4

# SUPPORTED_BACKENDS is now imported from backends package


class UnsupportedArchitectureError(RuntimeError):
    """Raised when the binary architecture is not currently supported."""


class UnsupportedBackendError(RuntimeError):
    """Raised when the requested disassembler backend is not available."""


@dataclass
class Instruction:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    groups: List[int]
    operands: List[object]


class Disassembly:
    """Lazy disassembly helper using Capstone."""

    def __init__(self, elf: ELFFile, include_bytes: bool) -> None:
        self.elf = elf
        self.include_bytes = include_bytes
        self.arch, self.mode = self._detect_arch()
        self.cs = self._init_capstone(self.arch, self.mode)
        self.instructions: Dict[int, Instruction] = {}
        self.addresses: List[int] = []
        self.section_bounds: List[Tuple[int, int]] = []
        self._disassemble()

    def _detect_arch(self) -> Tuple[int, int]:
        from capstone import CS_ARCH_X86, CS_MODE_64

        machine = self.elf.header["e_machine"]
        if machine != "EM_X86_64":
            raise UnsupportedArchitectureError(f"Unsupported architecture: {machine}")
        return CS_ARCH_X86, CS_MODE_64

    def _init_capstone(self, arch: int, mode: int):
        try:
            from capstone import Cs
        except ImportError as exc:  # pragma: no cover - dependency absent
            raise RuntimeError(
                "capstone is required for basic block analysis. Install dynint[analysis]"
            ) from exc
        cs = Cs(arch, mode)
        cs.detail = True
        return cs

    def _disassemble(self) -> None:
        for section in self.elf.iter_sections():
            sh_flags = section["sh_flags"]
            if not (sh_flags & SHF_EXECINSTR):
                continue
            try:
                data = section.data()
            except Exception:  # pragma: no cover - defensive
                continue
            addr = section["sh_addr"]
            size = section["sh_size"]
            self.section_bounds.append((addr, addr + size))
            for insn in self.cs.disasm(data, addr):
                operands = []
                try:
                    operands = list(insn.operands)
                except AttributeError:  # pragma: no cover - depends on arch
                    operands = []
                record = Instruction(
                    address=insn.address,
                    size=insn.size,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    bytes=bytes(insn.bytes) if self.include_bytes else b"",
                    groups=list(insn.groups),
                    operands=operands,
                )
                self.instructions[insn.address] = record
                self.addresses.append(insn.address)
        self.addresses.sort()

    def iter_function(self, start: int, end: int) -> Iterator[Instruction]:
        addr = start
        while addr < end:
            insn = self.instructions.get(addr)
            if not insn:
                break
            yield insn
            addr += insn.size

    def iter_all(self) -> Iterator[Instruction]:
        for addr in self.addresses:
            yield self.instructions[addr]


class BasicBlockBuilder:
    """Builds basic block layout for functions using disassembly."""

    def __init__(self, disasm: Disassembly) -> None:
        self.disasm = disasm

    def build(self, start: int, end: int) -> List[Dict[str, object]]:
        leaders = {start}
        body: List[Instruction] = list(self.disasm.iter_function(start, end))
        for insn in body:
            if self._is_branch(insn):
                target = self._branch_target(insn)
                if target is not None and start <= target < end:
                    leaders.add(target)
                fallthrough = insn.address + insn.size
                if self._falls_through(insn) and start <= fallthrough < end:
                    leaders.add(fallthrough)
        blocks: List[Dict[str, object]] = []
        sorted_leaders = sorted(leaders)
        for idx, leader in enumerate(sorted_leaders):
            block_end = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else end
            if block_end <= leader:
                continue
            size = block_end - leader
            successors = self._successors(body, leader, block_end, start, end)
            blocks.append(
                {
                    "addr": hex(leader),
                    "size": size,
                    "successors": [hex(succ) for succ in successors],
                }
            )
        return blocks

    def _is_branch(self, insn: Instruction) -> bool:
        from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET

        return any(group in insn.groups for group in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET))

    def _falls_through(self, insn: Instruction) -> bool:
        from capstone import CS_GRP_JUMP, CS_GRP_RET

        if CS_GRP_RET in insn.groups:
            return False
        if CS_GRP_JUMP in insn.groups and insn.mnemonic.startswith("jmp"):
            return False
        return True

    def _branch_target(self, insn: Instruction) -> Optional[int]:
        try:
            operand = insn.operands[0]
        except IndexError:
            return None
        try:
            from capstone.x86 import X86_OP_IMM
        except ImportError:  # pragma: no cover
            return None
        if getattr(operand, "type", None) == X86_OP_IMM:
            return int(getattr(operand, "imm", 0))
        return None

    def _successors(
        self,
        body: List[Instruction],
        leader: int,
        block_end: int,
        start: int,
        end: int,
    ) -> List[int]:
        last_insn = None
        for insn in body:
            if leader <= insn.address < block_end:
                last_insn = insn
        if not last_insn:
            return []
        successors: List[int] = []
        target = self._branch_target(last_insn)
        if target is not None and start <= target < end:
            successors.append(target)
        if self._falls_through(last_insn):
            fallthrough = last_insn.address + last_insn.size
            if start <= fallthrough < end:
                successors.append(fallthrough)
        return successors


class DwarfResolver:
    """Maps instruction addresses to DWARF file/line tuples."""

    def __init__(self, elf: ELFFile) -> None:
        self.available = False
        self._lookup: Dict[int, Tuple[str, int]] = {}
        if not elf.has_dwarf_info():
            return
        try:
            dwarf = elf.get_dwarf_info()
        except Exception:  # pragma: no cover - DWARF parsing failure
            return
        for cu in dwarf.iter_CUs():
            lineprog = dwarf.line_program_for_CU(cu)
            if not lineprog:
                continue
            header = lineprog.header
            include_dirs = [
                dir_entry.decode("utf-8", errors="ignore") if isinstance(dir_entry, bytes) else dir_entry
                for dir_entry in header.include_directory
            ]
            file_entries = header.file_entry
            for entry in lineprog.get_entries():
                state = entry.state
                if state is None or state.end_sequence:
                    continue
                file_index = (state.file or 0) - 1
                file_path = None
                if 0 <= file_index < len(file_entries):
                    fe = file_entries[file_index]
                    filename = fe.name.decode("utf-8", errors="ignore") if isinstance(fe.name, bytes) else fe.name
                    if fe.dir_index and 0 < fe.dir_index <= len(include_dirs):
                        directory = include_dirs[fe.dir_index - 1]
                        file_path = f"{directory}/{filename}" if directory else filename
                    else:
                        file_path = filename
                if file_path:
                    self._lookup.setdefault(state.address, (file_path, state.line or 0))
        self.available = bool(self._lookup)

    def lookup(self, addr: int) -> Optional[Tuple[str, int]]:
        return self._lookup.get(addr)


class ElfMapper:
    def __init__(
        self,
        binary_path: Path,
        only_external_calls: bool = False,
        include_dwarf: bool = False,
        include_bytes: bool = False,
        analysis_level: str = "basic-blocks",
        backend: str = "capstone",
        include_instructions: bool = False,
        include_behavior_algebra: bool = False,
    ) -> None:
        self.binary_path = binary_path
        self.only_external_calls = only_external_calls
        self.include_dwarf = include_dwarf
        self.include_bytes = include_bytes
        self.analysis_level = analysis_level
        self.backend = backend
        self.include_instructions = include_instructions
        self.include_behavior_algebra = include_behavior_algebra
        
        if backend not in SUPPORTED_BACKENDS:
            raise UnsupportedBackendError(f"Backend '{backend}' not supported. Available: {SUPPORTED_BACKENDS}")

    def run(self) -> Dict[str, Any]:
        """Run multi-backend analysis with unified output."""
        try:
            # Create and run backend analysis
            backend = create_backend(self.backend, self.binary_path)
            analysis_result = backend.analyze()
            
            # Build base result from backend analysis
            result = {
                "binary": analysis_result.binary_metadata,
                "disassembler": analysis_result.disassembler,
                "functions": analysis_result.functions,
                "callsites": analysis_result.callsites,
                "libraries": self._gather_libraries_elf(),
                "symbol_versions": self._gather_symbol_versions_elf(),
                "plt_entries": analysis_result.plt_entries,
            }
            
            # Add instruction-level data if requested
            if self.include_instructions:
                result["instructions"] = [
                    {
                        "address": instr.address,
                        "mnemonic": instr.mnemonic,
                        "operands": instr.operands,
                        "bytes": instr.bytes,
                        "size": instr.size
                    }
                    for instr in analysis_result.instructions
                ]
            
            # Add behavior algebra if requested
            if self.include_behavior_algebra:
                if analysis_result.instructions:
                    algebra = build_behavior_algebra(analysis_result.instructions)
                    result["behavior_algebra"] = algebra
                else:
                    result["behavior_algebra"] = "# No instructions available for behavior algebra generation"
            
            # Add DWARF information if requested
            if self.include_dwarf:
                self._add_dwarf_info(result)
            
            return result
            
        except Exception as e:
            LOGGER.error(f"Analysis failed with backend '{self.backend}': {e}")
            # Fallback to basic ELF metadata
            return {
                "binary": self._gather_metadata_elf(),
                "disassembler": "none",
                "functions": [],
                "callsites": [],
                "libraries": [],
                "symbol_versions": [],
                "error": str(e)
            }
    
    def _gather_metadata_elf(self) -> Dict[str, Any]:
        """Gather basic ELF metadata using pyelftools."""
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
        except Exception:
            return {
                "path": str(self.binary_path.resolve()),
                "pie": False,
                "image_base": 0,
                "entry": 0,
            }

    def _gather_libraries_elf(self) -> List[Dict[str, Any]]:
        """Extract library dependencies using pyelftools."""
        try:
            with self.binary_path.open("rb") as fp:
                elf = ELFFile(fp)
                return self._gather_libraries(elf)
        except Exception:
            return []

    def _gather_symbol_versions_elf(self) -> List[Dict[str, Any]]:
        """Extract symbol versions using pyelftools."""
        try:
            with self.binary_path.open("rb") as fp:
                elf = ELFFile(fp)
                return self._gather_symbol_versions(elf)
        except Exception:
            return []

    def _add_dwarf_info(self, result: Dict[str, Any]) -> None:
        """Add DWARF debugging information to callsites."""
        try:
            with self.binary_path.open("rb") as fp:
                elf = ELFFile(fp)
                dwarf = DwarfResolver(elf)
                if dwarf.available:
                    for callsite in result.get("callsites", []):
                        location = dwarf.lookup(int(callsite["at_addr"], 16))
                        if location:
                            callsite["file"], callsite["line"] = location
        except Exception as e:
            LOGGER.warning(f"DWARF processing failed: {e}")

    def _gather_metadata(self, elf: ELFFile) -> Dict[str, object]:
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

    def _gather_functions(
        self,
        elf: ELFFile,
        block_builder: Optional[BasicBlockBuilder],
    ) -> List[Dict[str, object]]:
        symbols = self._collect_function_symbols(elf)
        sorted_addrs = sorted(symbols)
        for idx, addr in enumerate(sorted_addrs):
            entry = symbols[addr]
            if entry["size"]:
                continue
            next_addr = sorted_addrs[idx + 1] if idx + 1 < len(sorted_addrs) else addr + max(entry["size"], 1)
            entry["size"] = max(1, next_addr - addr)
        results: List[Dict[str, object]] = []
        for addr in sorted_addrs:
            entry = symbols[addr]
            start = addr
            end = addr + max(entry["size"], 1)
            blocks = (
                block_builder.build(start, end) if block_builder else [
                    {
                        "addr": hex(start),
                        "size": entry["size"],
                        "successors": [],
                    }
                ]
            )
            results.append(
                {
                    "name": entry["name"],
                    "addr": hex(entry["addr"]),
                    "size": entry["size"],
                    "blocks": blocks,
                    "bind": entry["bind"],
                    "section": entry["section"],
                }
            )
        return results

    def _collect_function_symbols(self, elf: ELFFile) -> Dict[int, Dict[str, object]]:
        functions: Dict[int, Dict[str, object]] = {}
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
                entry = functions.setdefault(
                    addr,
                    {
                        "name": symbol.name or None,
                        "addr": addr,
                        "size": size,
                        "bind": symbol["st_info"]["bind"],
                        "section": str(symbol["st_shndx"]),
                    },
                )
                if size and not entry["size"]:
                    entry["size"] = size
                if symbol.name and not entry.get("name"):
                    entry["name"] = symbol.name
        return functions

    def _gather_plt_map(self, elf: ELFFile) -> Dict[int, str]:
        plt_map: Dict[int, str] = {}
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            try:
                target_section = elf.get_section(section["sh_info"])
            except Exception:  # pragma: no cover - unusual binaries
                continue
            if not target_section:
                continue
            name = target_section.name
            if not name or not name.startswith(".plt"):
                continue
            entry_size = target_section["sh_entsize"] or 16
            base_addr = target_section["sh_addr"]
            skip = 1 if name == ".plt" else 0
            for idx, reloc in enumerate(section.iter_relocations()):
                symbol = section.get_symbol(reloc.entry["r_info_sym"])
                if not symbol or not symbol.name:
                    continue
                plt_addr = base_addr + entry_size * (idx + skip)
                plt_map[plt_addr] = symbol.name
        return plt_map

    def _gather_callsites(
        self,
        elf: ELFFile,
        disasm: Optional[Disassembly],
        function_map: Dict[int, Dict[str, object]],
    ) -> List[Dict[str, object]]:
        if disasm is None:
            return []
        plt_map = self._gather_plt_map(elf)
        callsites: List[Dict[str, object]] = []
        try:
            from capstone.x86 import X86_OP_IMM
            from capstone import CS_GRP_CALL
        except ImportError:  # pragma: no cover
            return callsites
        for insn in disasm.iter_all():
            if CS_GRP_CALL not in insn.groups:
                continue
            entry: Dict[str, object] = {
                "at_addr": hex(insn.address),
                "type": "indirect",
                "target": None,
                "target_addr": None,
                "plt_addr": None,
                "size": insn.size,
            }
            operand = insn.operands[0] if insn.operands else None
            if operand is not None and getattr(operand, "type", None) == X86_OP_IMM:
                target = int(getattr(operand, "imm", 0))
                entry["target_addr"] = hex(target)
                entry["target"] = hex(target)
                entry["type"] = "direct"
                if target in plt_map:
                    entry["type"] = "plt"
                    entry["target"] = plt_map[target]
                    entry["plt_addr"] = hex(target)
                    entry["target_addr"] = hex(target)
                elif self.only_external_calls:
                    continue
                elif target in function_map:
                    entry["target"] = function_map[target].get("name") or hex(target)
            else:
                if self.only_external_calls:
                    continue
            if self.include_bytes:
                entry["bytes"] = insn.bytes.hex()
            callsites.append(entry)
        callsites.sort(key=lambda cs: int(str(cs["at_addr"]), 16))
        return callsites

    def _gather_libraries(self, elf: ELFFile) -> List[Dict[str, object]]:
        libraries: List[Dict[str, object]] = []
        dynamic = elf.get_section_by_name(".dynamic")
        needed: List[str] = []
        if dynamic:
            for tag in dynamic.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.append(tag.needed)
        ver_requirements = self._collect_version_requirements(elf)
        for soname in needed:
            entry = {"soname": soname, "needed": True}
            if soname in ver_requirements:
                entry["versions"] = sorted(ver_requirements[soname])
            libraries.append(entry)
        return libraries

    def _collect_version_requirements(self, elf: ELFFile) -> Dict[str, List[str]]:
        try:
            from elftools.elf.gnuversions import GNUVerNeedSection
        except ImportError:  # pragma: no cover
            return {}
        section = elf.get_section_by_name(".gnu.version_r")
        if section is None or not isinstance(section, GNUVerNeedSection):
            return {}
        requirements: Dict[str, List[str]] = {}
        for verneed in section.iter_versions():
            soname = getattr(verneed, "name", None)
            if not soname:
                continue
            versions = []
            for aux in verneed.iter_auxiliary():
                aux_name = getattr(aux, "name", None)
                if aux_name:
                    versions.append(aux_name)
            if versions:
                requirements[soname] = versions
        return requirements

    def _gather_symbol_versions(self, elf: ELFFile) -> List[Dict[str, object]]:
        dynsym = elf.get_section_by_name(".dynsym")
        if not dynsym or not isinstance(dynsym, SymbolTableSection):
            return []
        versions: List[Dict[str, object]] = []
        try:
            from elftools.elf.gnuversions import GNUVerSymSection, GNUVerNeedSection
        except ImportError:  # pragma: no cover
            return self._fallback_symbol_versions(dynsym)
        versym_section = elf.get_section_by_name(".gnu.version")
        if versym_section is None or not isinstance(versym_section, GNUVerSymSection):
            return self._fallback_symbol_versions(dynsym)
        verneed_section = elf.get_section_by_name(".gnu.version_r")
        index_to_lib: Dict[int, Tuple[str, str]] = {}
        if verneed_section and isinstance(verneed_section, GNUVerNeedSection):
            for verneed in verneed_section.iter_versions():
                for aux in verneed.iter_auxiliary():
                    other = getattr(aux, "other", None)
                    if other is None:
                        continue
                    index_to_lib[other] = (getattr(verneed, "name", None), getattr(aux, "name", None))
        for idx, ver in enumerate(versym_section.iter_symbol_versions()):
            symbol = dynsym.get_symbol(idx)
            if not symbol or not symbol.name:
                continue
            ver_name = getattr(ver, "name", None)
            if ver_name is None:
                continue
            is_default = bool(getattr(ver, "is_default", False))
            ver_index = getattr(ver, "index", None)
            lib_tuple = index_to_lib.get(ver_index)
            qualified = f"{symbol.name}{'@@' if is_default else '@'}{ver_name}"
            versions.append(
                {
                    "symbol": symbol.name,
                    "version": ver_name,
                    "qualified": qualified,
                    "library": lib_tuple[0] if lib_tuple else None,
                }
            )
        if not versions:
            return self._fallback_symbol_versions(dynsym)
        return versions

    def _fallback_symbol_versions(self, dynsym: SymbolTableSection) -> List[Dict[str, object]]:
        results: List[Dict[str, object]] = []
        for symbol in dynsym.iter_symbols():
            name = symbol.name
            if not name or "@" not in name:
                continue
            base, version = name.split("@", 1)
            default = version.startswith("@")
            version = version.lstrip("@")
            qualified = f"{base}{'@@' if default else '@'}{version}"
            results.append(
                {
                    "symbol": base,
                    "version": version,
                    "qualified": qualified,
                    "library": None,
                }
            )
        return results


def export_structured_analysis(
    binary_path: Path,
    output_base_dir: Path,
    only_external_calls: bool = False,
    include_dwarf: bool = False,
    include_bytes: bool = False,
    analysis_level: str = "basic-blocks",
    backend: str = "capstone",
    include_instructions: bool = False,
    include_behavior_algebra: bool = False,
) -> Path:
    """Export analysis to a structured directory with separate files.
    
    Creates a timestamped directory containing:
    - analysis.json (complete analysis)
    - functions.json (functions only)
    - instructions.json (instructions only, if requested)
    - behavior_algebra.txt (behavior algebra, if requested)
    
    Args:
        binary_path: Path to binary file
        output_base_dir: Base directory for exports
        only_external_calls: Only include external function calls
        include_dwarf: Include DWARF debugging information
        include_bytes: Include instruction bytes in output
        analysis_level: Level of analysis ("basic-blocks" or "instructions")
        backend: Disassembler backend ("capstone", "angr", "objdump")
        include_instructions: Include instruction-level disassembly
        include_behavior_algebra: Include behavior algebra generation
    
    Returns:
        Path to created export directory
    """
    # Create timestamped directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    binary_name = binary_path.stem
    export_dir = output_base_dir / f"{binary_name}_{backend}_{timestamp}"
    export_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate analysis
    mapper = ElfMapper(
        binary_path=binary_path,
        only_external_calls=only_external_calls,
        include_dwarf=include_dwarf,
        include_bytes=include_bytes,
        analysis_level=analysis_level,
        backend=backend,
        include_instructions=include_instructions,
        include_behavior_algebra=include_behavior_algebra,
    )
    analysis_result = mapper.run()
    
    # Export complete analysis
    analysis_file = export_dir / "analysis.json"
    with analysis_file.open("w") as f:
        json.dump(analysis_result, f, indent=2)
    
    # Export functions separately
    functions_file = export_dir / "functions.json"
    functions_data = {
        "binary": analysis_result.get("binary", {}),
        "disassembler": analysis_result.get("disassembler", backend),
        "functions": analysis_result.get("functions", []),
        "callsites": analysis_result.get("callsites", []),
        "plt_entries": analysis_result.get("plt_entries", {}),
    }
    with functions_file.open("w") as f:
        json.dump(functions_data, f, indent=2)
    
    # Export instructions if requested
    if include_instructions and analysis_result.get("instructions"):
        instructions_file = export_dir / "instructions.json"
        instructions_data = {
            "binary": analysis_result.get("binary", {}),
            "disassembler": analysis_result.get("disassembler", backend),
            "instructions": analysis_result.get("instructions", []),
            "total_instructions": len(analysis_result.get("instructions", [])),
        }
        with instructions_file.open("w") as f:
            json.dump(instructions_data, f, indent=2)
    
    # Export behavior algebra if requested
    if include_behavior_algebra and analysis_result.get("behavior_algebra"):
        algebra_file = export_dir / "behavior_algebra.txt"
        with algebra_file.open("w") as f:
            f.write(analysis_result["behavior_algebra"])
    
    # Create summary file
    summary_file = export_dir / "summary.txt"
    with summary_file.open("w") as f:
        f.write(f"Static Analysis Summary\n")
        f.write(f"======================\n")
        f.write(f"Binary: {binary_path}\n")
        f.write(f"Backend: {backend}\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"Functions: {len(analysis_result.get('functions', []))}\n")
        f.write(f"Callsites: {len(analysis_result.get('callsites', []))}\n")
        if include_instructions:
            f.write(f"Instructions: {len(analysis_result.get('instructions', []))}\n")
        if include_behavior_algebra:
            f.write(f"Behavior algebra: {'Yes' if analysis_result.get('behavior_algebra') else 'No'}\n")
        f.write(f"\nFiles created:\n")
        f.write(f"- analysis.json (complete analysis)\n")
        f.write(f"- functions.json (functions and callsites)\n")
        if include_instructions:
            f.write(f"- instructions.json (instruction-level disassembly)\n")
        if include_behavior_algebra:
            f.write(f"- behavior_algebra.txt (behavior algebra representation)\n")
        f.write(f"- summary.txt (this file)\n")
    
    return export_dir


def generate_map(
    binary_path: Path,
    only_external_calls: bool = False,
    include_dwarf: bool = False,
    include_bytes: bool = False,
    analysis_level: str = "basic-blocks",
    backend: str = "capstone",
    include_instructions: bool = False,
    include_behavior_algebra: bool = False,
) -> Dict[str, Any]:
    """Generate comprehensive binary analysis using specified disassembler backend.
    
    Args:
        binary_path: Path to binary file
        only_external_calls: Only include external function calls
        include_dwarf: Include DWARF debugging information
        include_bytes: Include instruction bytes in output
        analysis_level: Level of analysis ("basic-blocks" or "instructions")
        backend: Disassembler backend ("capstone", "angr", "objdump")
        include_instructions: Include instruction-level disassembly
        include_behavior_algebra: Include behavior algebra generation
    
    Returns:
        Comprehensive analysis results dictionary
    """
    mapper = ElfMapper(
        binary_path=binary_path,
        only_external_calls=only_external_calls,
        include_dwarf=include_dwarf,
        include_bytes=include_bytes,
        analysis_level=analysis_level,
        backend=backend,
        include_instructions=include_instructions,
        include_behavior_algebra=include_behavior_algebra,
    )
    return mapper.run()


# Convenience functions for backward compatibility
def disassemble_with_capstone(binary_path: Path) -> List[InstructionRecord]:
    """Quick disassembly using Capstone backend."""
    backend = create_backend("capstone", binary_path)
    return backend.disassemble()


def generate_behavior_algebra(binary_path: Path, backend: str = "capstone") -> str:
    """Generate behavior algebra using specified backend."""
    disasm_backend = create_backend(backend, binary_path)
    instructions = disasm_backend.disassemble()
    return build_behavior_algebra(instructions) if instructions else ""


# get_available_backends is now imported from backends package
