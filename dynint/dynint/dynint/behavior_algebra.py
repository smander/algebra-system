"""Behavior algebra generation for binary analysis."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Set


# Control flow constants
_CONTROL_FLOW_PREFIXES = ("j",)
_CONTROL_FLOW_TERMINATORS = {"ret", "return"}
_CALL_MNEMONIC = "call"
_UNCONDITIONAL_JUMP = "jmp"
_DYNAMIC_OPERATORS = ["+", "-", "*", "×", "·"]


@dataclass
class InstructionRecord:
    """Instruction representation for behavior algebra generation."""
    address: str
    mnemonic: str
    operands: str = ""
    bytes: str = ""
    size: int = 0


def _is_dynamic_operand(operand: str) -> bool:
    """Detect if operand represents dynamic/indirect addressing."""
    operand = operand.strip()
    if not operand:
        return False

    token = operand.split()[0]
    if token.startswith("0x"):
        return False
    if all(ch in "0123456789abcdef" for ch in token.lower()):
        return False

    if "ptr" in operand and "[" not in operand:
        return True

    registers = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
        "rip", "eip", "ip",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
        "cs", "ds", "es", "fs", "gs", "ss",
    }

    if "[" in operand and "]" in operand:
        inside = operand[operand.find("[") + 1:operand.find("]")]
        if any(reg in inside for reg in registers):
            return True
        if any(op in inside for op in _DYNAMIC_OPERATORS):
            parts = None
            for op in _DYNAMIC_OPERATORS:
                if op in inside:
                    parts = inside.split(op, 1)
                    break
            if parts and len(parts) == 2:
                left, right = parts[0].strip(), parts[1].strip()
                left_numeric = left.startswith("0x") or left.isdigit()
                right_numeric = right.startswith("0x") or right.isdigit()
                if left_numeric and right_numeric:
                    return False
            return True
        if inside.startswith("0x") or inside.isdigit():
            return False
        return True

    return False


def _extract_static_target(operands: str) -> Optional[str]:
    """Extract static address from operands."""
    if not operands:
        return None
    operands = operands.replace(",", " ")
    for token in operands.split():
        token = token.strip()
        if not token:
            continue
        if token.startswith("0x"):
            try:
                return f"{int(token, 16):x}"
            except ValueError:
                continue
        if all(ch in "0123456789abcdef" for ch in token.lower()):
            try:
                return f"{int(token, 16):x}"
            except ValueError:
                continue
    return None


def _compute_jump_targets(instructions: Sequence[InstructionRecord]) -> Set[str]:
    """Compute all static jump/call targets."""
    targets: Set[str] = set()
    for instr in instructions:
        if instr.mnemonic == _CALL_MNEMONIC or instr.mnemonic.startswith(_CONTROL_FLOW_PREFIXES):
            if instr.operands and not _is_dynamic_operand(instr.operands):
                target = _extract_static_target(instr.operands)
                if target:
                    targets.add(target)
    return targets


def build_behavior_algebra(instructions: Sequence[InstructionRecord]) -> str:
    """Generate behavior algebra representation from instruction sequence."""
    if not instructions:
        return ""

    jump_targets = _compute_jump_targets(instructions)
    dynamic_behaviors: Set[str] = set()
    processed_addresses: Set[str] = set()
    lines: List[str] = []

    i = 0
    while i < len(instructions):
        current = instructions[i]
        addr = current.address
        mnemonic = current.mnemonic

        if addr in processed_addresses:
            i += 1
            continue

        processed_addresses.add(addr)

        # Handle return instructions
        if mnemonic in _CONTROL_FLOW_TERMINATORS:
            lines.append(f"B({addr}) = ret({addr}),")
            i += 1
            continue

        # Handle call instructions
        if mnemonic == _CALL_MNEMONIC:
            destination = current.operands
            is_dynamic = _is_dynamic_operand(destination)

            if is_dynamic:
                dynamic_behaviors.add(f"call({addr}):{destination}")
                next_idx = i + 1
                if next_idx < len(instructions):
                    lines.append(
                        f"B({addr}) = B(DYNAMIC); B({instructions[next_idx].address}),"
                    )
                else:
                    lines.append(f"B({addr}) = B(DYNAMIC),")
            else:
                clean_dest = _extract_static_target(destination)
                if clean_dest is None:
                    clean_dest = destination
                next_idx = i + 1
                if next_idx < len(instructions):
                    lines.append(
                        f"B({addr}) = B({clean_dest}); B({instructions[next_idx].address}),"
                    )
                else:
                    lines.append(f"B({addr}) = B({clean_dest}),")
            i += 1
            continue

        # Handle jump instructions
        if mnemonic.startswith(_CONTROL_FLOW_PREFIXES):
            destination = current.operands
            is_dynamic = _is_dynamic_operand(destination)

            if is_dynamic:
                dynamic_behaviors.add(f"{mnemonic}({addr}):{destination}")
                if mnemonic != _UNCONDITIONAL_JUMP:
                    next_idx = i + 1
                    if next_idx < len(instructions):
                        lines.append(
                            f"B({addr}) = {mnemonic}({addr}).B(DYNAMIC) + !{mnemonic}({addr}).B({instructions[next_idx].address}),"
                        )
                    else:
                        fallthrough = f"{int(addr, 16) + 1:x}"
                        lines.append(
                            f"B({addr}) = {mnemonic}({addr}).B(DYNAMIC) + !{mnemonic}({addr}).B({fallthrough}),"
                        )
                else:
                    lines.append(f"B({addr}) = B(DYNAMIC),")
            else:
                clean_dest = _extract_static_target(destination)
                if clean_dest is None:
                    clean_dest = destination
                next_idx = i + 1
                if next_idx < len(instructions):
                    if mnemonic == _UNCONDITIONAL_JUMP:
                        lines.append(f"B({addr}) = B({clean_dest}),")
                    else:
                        lines.append(
                            f"B({addr}) = {mnemonic}({addr}).B({clean_dest}) + !{mnemonic}({addr}).B({instructions[next_idx].address}),"
                        )
                else:
                    if mnemonic == _UNCONDITIONAL_JUMP:
                        lines.append(f"B({addr}) = B({clean_dest}),")
                    else:
                        fallthrough = f"{int(addr, 16) + 1:x}"
                        lines.append(
                            f"B({addr}) = {mnemonic}({addr}).B({clean_dest}) + !{mnemonic}({addr}).B({fallthrough}),"
                        )
            i += 1
            continue

        # Handle sequential instruction blocks
        start_addr = addr
        seq_parts: List[str] = []
        initial_i = i

        while i < len(instructions):
            current = instructions[i]
            mnemonic = current.mnemonic
            next_is_jump_target = i + 1 < len(instructions) and instructions[i + 1].address in jump_targets
            ends_sequence = (
                mnemonic == _CALL_MNEMONIC
                or mnemonic.startswith(_CONTROL_FLOW_PREFIXES)
                or mnemonic in _CONTROL_FLOW_TERMINATORS
                or next_is_jump_target
            )
            seq_parts.append(f"{mnemonic}({current.address})")
            i += 1
            if ends_sequence:
                break

        if i == initial_i:
            i += 1
            continue

        if i < len(instructions):
            lines.append(
                f"B({start_addr}) = {'.'.join(seq_parts)}.B({instructions[i].address}),"
            )
        else:
            fallthrough = f"{int(instructions[-1].address, 16) + 1:x}"
            lines.append(f"B({start_addr}) = {'.'.join(seq_parts)}.B({fallthrough}),")

    lines.append("\n# Dynamic (indirect) control flows:")
    lines.append("B(DYNAMIC) = nop(DYNAMIC),")

    if dynamic_behaviors:
        lines.append("\n# Observed dynamic control transfers:")
        for entry in sorted(dynamic_behaviors):
            lines.append(f"# {entry}")

    return "\n".join(lines)


def instructions_from_static_json(functions_data: List[dict]) -> List[InstructionRecord]:
    """Convert static analysis JSON function data to instruction records."""
    # This is a placeholder - will be implemented when we have instruction-level data
    # For now, create minimal records from function/block boundaries
    instructions = []
    
    for func in functions_data:
        addr = func.get("addr", "0x0").replace("0x", "")
        instructions.append(InstructionRecord(
            address=addr,
            mnemonic="func_start",
            operands="",
            bytes="",
            size=0
        ))
    
    return instructions