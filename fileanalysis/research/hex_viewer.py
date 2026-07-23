
"""Interactive hex viewer with binary annotations for file research."""

from __future__ import annotations

import sys
import struct
import tty
import termios
from dataclasses import dataclass
from pathlib import Path

import capstone
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings

from fileanalysis.intelligence.asm_insights import ASMInsightsGenerator


# ─── Annotation Data ────────────────────────────────────────────────

@dataclass
class Annotation:
    """A labelled region inside the binary."""
    offset: int
    length: int
    label: str
    style: str = "bold yellow"  # Rich markup style


# ─── Known byte-pattern signatures ─────────────────────────────────

HEADER_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"MZ",             "DOS / PE Header (MZ magic)",              "bold red"),
    (b"\x7fELF",        "ELF Header",                              "bold red"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit",                        "bold red"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit",                        "bold red"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (reversed)",             "bold red"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit (reversed)",             "bold red"),
    (b"\xca\xfe\xba\xbe", "Mach-O Universal / Java class",        "bold red"),
    (b"PK\x03\x04",     "ZIP / OOXML Archive",                     "bold red"),
    (b"%PDF",           "PDF Document",                             "bold red"),
    (b"\xd0\xcf\x11\xe0", "OLE Compound (MS Office legacy)",      "bold red"),
    (b"\x89PNG",        "PNG Image",                                "bold blue"),
    (b"\xff\xd8\xff",   "JPEG Image",                               "bold blue"),
    (b"GIF8",           "GIF Image",                                "bold blue"),
    (b"RIFF",           "RIFF Container (AVI/WAV)",                 "bold blue"),
]

# Suspicious byte runs
SUSPICIOUS_PATTERNS: list[tuple[bytes, int, str, str]] = [
    # (pattern_byte, min_run_length, label, style)
    (b"\x90", 4, "NOP Sled (potential shellcode runway)", "bold red"),
    (b"\xCC", 4, "INT3 Breakpoint Sled (anti-debug / padding)", "bold magenta"),
    (b"\x00", 16, "Null Padding", "dim"),
]

# Well-known PE field offsets (relative to DOS header start at 0)
PE_DOS_FIELDS: list[tuple[int, int, str]] = [
    (0x00, 2,  "e_magic (MZ)"),
    (0x3C, 4,  "e_lfanew → PE header offset"),
]

# Suspicious API names to highlight in ASCII column
SUSPICIOUS_APIS = {
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "NtUnmapViewOfSection", "IsDebuggerPresent", "WinExec",
    "ShellExecute", "CreateProcess", "RegSetValueEx",
    "InternetOpen", "URLDownload", "HttpSendRequest",
    "CryptEncrypt", "CryptDecrypt", "VirtualProtect",
    "LoadLibrary", "GetProcAddress", "NtQueryInformation",
}

# Suspicious assembly mnemonics/patterns → threat description
# Each entry: (match_function, threat_label)
# match_function receives (mnemonic, op_str) and returns True if suspicious
SUSPICIOUS_ASM_PATTERNS: list[tuple[callable, str]] = [
    # Syscall / interrupt-based execution
    (lambda m, o: m == "syscall",                        "Direct syscall (evasion / shellcode)"),
    (lambda m, o: m == "sysenter",                       "Sysenter (evasion / shellcode)"),
    (lambda m, o: m == "int" and "0x80" in o,            "Linux syscall via int 0x80"),
    (lambda m, o: m == "int" and "0x2e" in o,            "NT syscall via int 0x2e"),
    (lambda m, o: m == "int3" or (m == "int" and "3" in o), "INT3 breakpoint (anti-debug)"),
    # Anti-debugging / anti-VM
    (lambda m, o: m == "cpuid",                          "CPUID (VM / sandbox detection)"),
    (lambda m, o: m == "rdtsc",                          "RDTSC (timing-based anti-debug)"),
    (lambda m, o: m == "rdtscp",                         "RDTSCP (timing-based anti-debug)"),
    (lambda m, o: m in ("sidt", "sgdt", "sldt", "str"),  "Privileged table read (VM detection)"),
    # Self-modifying / shellcode tricks
    (lambda m, o: m == "call" and o.startswith("0x") and abs(int(o, 16)) < 0x10, "Call-to-self (shellcode decoder)"),
    (lambda m, o: m == "xor" and len(o.split(",")) == 2 and o.split(",")[0].strip() == o.split(",")[1].strip(), "XOR reg, reg (zeroing / decode loop)"),
    # Process injection patterns
    (lambda m, o: m == "call" and "rax" in o,            "Indirect call via RAX (dynamic API)"),
    (lambda m, o: m == "call" and "rbx" in o,            "Indirect call via RBX (dynamic API)"),
    (lambda m, o: m == "call" and "r10" in o,            "Indirect call via R10 (dynamic API)"),
    (lambda m, o: m == "call" and "r11" in o,            "Indirect call via R11 (dynamic API)"),
    (lambda m, o: m == "jmp" and "rax" in o,             "Indirect jump via RAX (dynamic dispatch)"),
    (lambda m, o: m == "jmp" and "qword ptr" in o,       "Indirect jump via memory (IAT/hook)"),
    (lambda m, o: m == "call" and "qword ptr" in o,      "Indirect call via memory (IAT/hook)"),
    # Stack pivoting / ROP
    (lambda m, o: m == "xchg" and "esp" in o,            "Stack pivot (ROP chain setup)"),
    (lambda m, o: m == "xchg" and "rsp" in o,            "Stack pivot (ROP chain setup)"),
    # Heaven's Gate
    (lambda m, o: m == "retf",                           "Far return (Heaven's Gate / mode switch)"),
    (lambda m, o: m == "ljmp" or (m == "jmp" and "far" in o), "Far jump (Heaven's Gate / mode switch)"),
]


# ─── Binary Annotator ──────────────────────────────────────────────

class BinaryAnnotator:
    """Scans raw bytes and produces a list of Annotations."""

    def annotate(self, data: bytes) -> list[Annotation]:
        annotations: list[Annotation] = []

        # 1. File header signatures
        for sig, label, style in HEADER_SIGNATURES:
            if data[:len(sig)] == sig:
                annotations.append(Annotation(0, len(sig), label, style))
                break

        # 2. PE-specific deep annotations
        if data[:2] == b"MZ" and len(data) > 0x40:
            self._annotate_pe(data, annotations)

        # 3. ELF-specific deep annotations
        if data[:4] == b"\x7fELF" and len(data) > 0x40:
            self._annotate_elf(data, annotations)

        # 4. Suspicious byte runs (NOP sleds, INT3 padding, null runs)
        self._annotate_runs(data, annotations)

        # 5. Embedded readable strings (>= 6 chars)
        self._annotate_strings(data, annotations)

        # Sort by offset for display
        annotations.sort(key=lambda a: a.offset)
        return annotations

    # ── PE ───────────────────────────────────────────────────
    def _annotate_pe(self, data: bytes, out: list[Annotation]) -> None:
        # e_lfanew field
        out.append(Annotation(0x3C, 4, "e_lfanew (PE header offset pointer)", "bold cyan"))

        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        except struct.error:
            return

        if pe_offset + 24 > len(data):
            return

        # PE\0\0 signature
        if data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            out.append(Annotation(pe_offset, 4, "PE Signature", "bold red"))

            # COFF header (20 bytes after PE sig)
            coff_off = pe_offset + 4
            if coff_off + 20 <= len(data):
                out.append(Annotation(coff_off, 2, "COFF: Machine type", "bold green"))
                out.append(Annotation(coff_off + 2, 2, "COFF: Number of sections", "bold green"))
                out.append(Annotation(coff_off + 4, 4, "COFF: TimeDateStamp", "bold green"))
                out.append(Annotation(coff_off + 16, 2, "COFF: SizeOfOptionalHeader", "bold green"))
                out.append(Annotation(coff_off + 18, 2, "COFF: Characteristics", "bold green"))

            # Optional header magic
            opt_off = coff_off + 20
            if opt_off + 2 <= len(data):
                magic = struct.unpack_from("<H", data, opt_off)[0]
                if magic == 0x10B:
                    out.append(Annotation(opt_off, 2, "Optional Header: PE32 (32-bit)", "bold yellow"))
                elif magic == 0x20B:
                    out.append(Annotation(opt_off, 2, "Optional Header: PE32+ (64-bit)", "bold yellow"))

            # Entry point
            ep_off = opt_off + 16
            if ep_off + 4 <= len(data):
                out.append(Annotation(ep_off, 4, "AddressOfEntryPoint", "bold red"))

    # ── ELF ──────────────────────────────────────────────────
    def _annotate_elf(self, data: bytes, out: list[Annotation]) -> None:
        out.append(Annotation(0x04, 1, "ELF Class (1=32-bit, 2=64-bit)", "bold cyan"))
        out.append(Annotation(0x05, 1, "ELF Data Encoding (1=LE, 2=BE)", "bold cyan"))
        out.append(Annotation(0x07, 1, "ELF OS/ABI", "bold cyan"))

        if len(data) > 0x12:
            out.append(Annotation(0x10, 2, "ELF Type (EXEC/DYN/REL)", "bold green"))

        if len(data) > 0x18:
            # 64-bit entry point
            ei_class = data[0x04]
            if ei_class == 2 and len(data) > 0x20:
                out.append(Annotation(0x18, 8, "ELF Entry Point (64-bit)", "bold red"))
            elif ei_class == 1 and len(data) > 0x1C:
                out.append(Annotation(0x18, 4, "ELF Entry Point (32-bit)", "bold red"))

    # ── Byte runs ────────────────────────────────────────────
    def _annotate_runs(self, data: bytes, out: list[Annotation]) -> None:
        for pat_byte, min_len, label, style in SUSPICIOUS_PATTERNS:
            i = 0
            byte_val = pat_byte[0]
            while i < len(data):
                if data[i] == byte_val:
                    run_start = i
                    while i < len(data) and data[i] == byte_val:
                        i += 1
                    run_len = i - run_start
                    if run_len >= min_len:
                        out.append(Annotation(run_start, run_len, f"{label} ({run_len} bytes)", style))
                else:
                    i += 1

    # ── Strings ──────────────────────────────────────────────
    def _annotate_strings(self, data: bytes, out: list[Annotation]) -> None:
        i = 0
        min_len = 6
        while i < len(data):
            if 32 <= data[i] <= 126:
                start = i
                while i < len(data) and 32 <= data[i] <= 126:
                    i += 1
                length = i - start
                if length >= min_len:
                    s = data[start:start + length].decode("ascii", errors="replace")
                    # Check if it contains a suspicious API name
                    is_suspicious = any(api in s for api in SUSPICIOUS_APIS)
                    style = "bold red" if is_suspicious else "green"
                    label = f'String: "{s[:60]}"'
                    if is_suspicious:
                        label += " [SUSPICIOUS API]"
                    out.append(Annotation(start, length, label, style))
            else:
                i += 1


from dataclasses import dataclass

@dataclass
class BasicBlock:
    id_addr: int
    instructions: list[tuple[int, str]]
    successors: list[int]

# ─── Disassembler Helper ───────────────────────────────────────────

class Disassembler:
    """Detects architecture from binary headers and disassembles code sections."""

    def __init__(self, data: bytes, console: Console | None = None):
        self.data = data
        self.arch = None
        self.mode = None
        self.md = None
        # code_sections: list of (file_offset, size) for executable sections
        self.code_sections: list[tuple[int, int]] = []
        # Precomputed: file_offset → assembly string
        self._asm_cache: dict[int, str] = {}

        self._detect_and_init(console)

    def _detect_and_init(self, console: Console | None = None) -> None:
        """Detect arch from file headers and locate code sections."""
        data = self.data

        # ── PE ──
        if data[:2] == b"MZ" and len(data) > 0x40:
            try:
                pe_off = struct.unpack_from("<I", data, 0x3C)[0]
                if data[pe_off:pe_off + 4] == b"PE\x00\x00":
                    machine = struct.unpack_from("<H", data, pe_off + 4)[0]
                    if machine == 0x8664:  # AMD64
                        self.arch, self.mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
                    elif machine == 0x14C:  # i386
                        self.arch, self.mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
                    elif machine == 0xAA64:  # ARM64
                        self.arch, self.mode = capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
                    else:
                        return

                    # Parse section table to find .text
                    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
                    opt_hdr_size = struct.unpack_from("<H", data, pe_off + 20)[0]
                    section_table = pe_off + 24 + opt_hdr_size

                    for i in range(num_sections):
                        sec_off = section_table + i * 40
                        if sec_off + 40 > len(data):
                            break
                        name = data[sec_off:sec_off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
                        raw_size = struct.unpack_from("<I", data, sec_off + 16)[0]
                        raw_ptr = struct.unpack_from("<I", data, sec_off + 20)[0]
                        chars = struct.unpack_from("<I", data, sec_off + 36)[0]
                        # IMAGE_SCN_CNT_CODE (0x20) or IMAGE_SCN_MEM_EXECUTE (0x20000000)
                        if chars & 0x20 or chars & 0x20000000:
                            self.code_sections.append((raw_ptr, raw_size))
            except (struct.error, IndexError):
                pass

        # ── ELF ──
        elif data[:4] == b"\x7fELF" and len(data) > 0x40:
            try:
                ei_class = data[4]  # 1=32, 2=64
                e_machine_off = 0x12
                e_machine = struct.unpack_from("<H", data, e_machine_off)[0]

                if e_machine == 0x3E:  # x86-64
                    self.arch, self.mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
                elif e_machine == 0x03:  # i386
                    self.arch, self.mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
                elif e_machine == 0xB7:  # AArch64
                    self.arch, self.mode = capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
                else:
                    return

                # Parse section headers to find executable sections
                if ei_class == 2:  # 64-bit
                    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
                    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
                    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
                else:  # 32-bit
                    e_shoff = struct.unpack_from("<I", data, 0x20)[0]
                    e_shentsize = struct.unpack_from("<H", data, 0x2E)[0]
                    e_shnum = struct.unpack_from("<H", data, 0x30)[0]

                for i in range(e_shnum):
                    sh_off = e_shoff + i * e_shentsize
                    if sh_off + e_shentsize > len(data):
                        break
                    if ei_class == 2:
                        sh_flags = struct.unpack_from("<Q", data, sh_off + 8)[0]
                        sh_offset = struct.unpack_from("<Q", data, sh_off + 24)[0]
                        sh_size = struct.unpack_from("<Q", data, sh_off + 32)[0]
                    else:
                        sh_flags = struct.unpack_from("<I", data, sh_off + 8)[0]
                        sh_offset = struct.unpack_from("<I", data, sh_off + 16)[0]
                        sh_size = struct.unpack_from("<I", data, sh_off + 20)[0]
                    # SHF_EXECINSTR = 0x4
                    if sh_flags & 0x4:
                        self.code_sections.append((sh_offset, sh_size))
            except (struct.error, IndexError):
                pass

        if self.arch is not None:
            self.md = capstone.Cs(self.arch, self.mode)
            self.md.skipdata = True
            self._disassemble_sections(console)

    def _disassemble_sections(self, console: Console | None = None) -> None:
        """Pre-disassemble all code sections and cache by file offset."""
        if not self.md:
            return
            
        total_size = sum(sz for _, sz in self.code_sections)
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
        
        progress = None
        if console and total_size > 0:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            )
            task_id = progress.add_task("[cyan]Disassembling binary...", total=total_size)
            progress.start()
            
        try:
            for sec_offset, sec_size in self.code_sections:
                code = self.data[sec_offset:sec_offset + sec_size]
                last_addr = sec_offset
                for insn in self.md.disasm(code, sec_offset):
                    self._asm_cache[insn.address] = f"{insn.mnemonic} {insn.op_str}".strip()
                    if progress and len(self._asm_cache) % 2000 == 0:
                        progress.update(task_id, advance=(insn.address - last_addr))
                        last_addr = insn.address
                
                if progress:
                    progress.update(task_id, advance=(sec_offset + sec_size - last_addr))
        finally:
            if progress:
                progress.stop()

    def get_asm_at(self, offset: int) -> str | None:
        """Return the assembly instruction at the given file offset, or None."""
        return self._asm_cache.get(offset)

    def is_code_offset(self, offset: int) -> bool:
        """Check if an offset falls within a code section."""
        for sec_off, sec_size in self.code_sections:
            if sec_off <= offset < sec_off + sec_size:
                return True
        return False

    def extract_cfg(self, start_offset: int, max_blocks: int = 15) -> list[BasicBlock]:
        """Extract an intra-procedural CFG starting from start_offset."""
        if not self.md or not self.is_code_offset(start_offset):
            return []

        self.md.detail = True
        blocks = {}
        queue = [start_offset]
        seen = set()

        while queue and len(blocks) < max_blocks:
            current_addr = queue.pop(0)
            if current_addr in seen:
                continue
            seen.add(current_addr)
            
            # Find which section we are in
            sec_start, sec_size = 0, 0
            for off, sz in self.code_sections:
                if off <= current_addr < off + sz:
                    sec_start, sec_size = off, sz
                    break
            
            if not sec_start:
                continue
                
            code_chunk = self.data[current_addr : sec_start + sec_size]
            
            block_insns = []
            successors = []
            block_addr = current_addr
            
            # Disassemble from current_addr
            for insn in self.md.disasm(code_chunk, current_addr):
                asm_str = f"{insn.mnemonic} {insn.op_str}".strip()
                block_insns.append((insn.address, asm_str))
                
                # Check branch
                is_jmp, is_call, is_ret = False, False, False
                try:
                    is_jmp = capstone.CS_GRP_JUMP in insn.groups
                    is_call = capstone.CS_GRP_CALL in insn.groups
                    is_ret = capstone.CS_GRP_RET in insn.groups
                except capstone.CsError:
                    pass
                
                if is_jmp or is_call or is_ret:
                    target = None
                    try:
                        if insn.op_str.startswith("0x"):
                            target = int(insn.op_str, 16)
                    except ValueError:
                        pass
                        
                    if is_jmp:
                        # Conditional jumps have both target and fallthrough
                        if insn.mnemonic != "jmp":
                            fallthrough = insn.address + insn.size
                            successors.append(fallthrough)
                            if fallthrough not in seen and fallthrough not in queue:
                                queue.append(fallthrough)
                                
                        if target:
                            successors.append(target)
                            if target not in seen and target not in queue:
                                queue.append(target)
                    
                    elif is_call:
                        # Treat call as sequential intra-procedural flow
                        fallthrough = insn.address + insn.size
                        successors.append(fallthrough)
                        if fallthrough not in seen and fallthrough not in queue:
                            queue.append(fallthrough)
                            
                    break
                    
            if block_insns:
                blocks[block_addr] = BasicBlock(id_addr=block_addr, instructions=block_insns, successors=successors)
                
        self.md.detail = False
        return list(blocks.values())


# ─── Interactive Hex Viewer ─────────────────────────────────────────

class HexViewer:
    """Paginated, annotated hex dump rendered with Rich."""

    BYTES_PER_ROW = 16
    ROWS_PER_PAGE = 32  # 32 rows × 16 bytes = 512 bytes per page

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.data = Path(file_path).read_bytes()
        self.console = Console()
        self.annotator = BinaryAnnotator()
        self.annotations = self.annotator.annotate(self.data)
        # Build a quick lookup: offset → annotation
        self._ann_map: dict[int, Annotation] = {}
        for ann in self.annotations:
            # Store annotation at its start offset
            if ann.offset not in self._ann_map:
                self._ann_map[ann.offset] = ann

        # Disassembler
        self.disasm = Disassembler(self.data, console=self.console)
        if self.disasm.code_sections:
            arch_name = {capstone.CS_ARCH_X86: "x86", capstone.CS_ARCH_ARM64: "ARM64"}.get(self.disasm.arch, "unknown")
            mode_name = {capstone.CS_MODE_32: "32-bit", capstone.CS_MODE_64: "64-bit", capstone.CS_MODE_ARM: ""}.get(self.disasm.mode, "")
            self.console.print(f"[green]Detected {arch_name} {mode_name} — {len(self.disasm._asm_cache):,} instructions disassembled[/]")
        else:
            self.console.print("[yellow]No executable code sections found for disassembly.[/]")

    def _get_annotation_for_row(self, row_offset: int) -> Annotation | None:
        """Find the most relevant annotation that overlaps this 16-byte row."""
        for ann in self.annotations:
            ann_end = ann.offset + ann.length
            row_end = row_offset + self.BYTES_PER_ROW
            # Check overlap
            if ann.offset < row_end and ann_end > row_offset:
                return ann
        return None

    def _render_row(self, offset: int) -> tuple[Text, Text, Text, Text, Text]:
        """Render a single 16-byte row as (offset, hex, ascii, annotation, assembly)."""
        chunk = self.data[offset:offset + self.BYTES_PER_ROW]

        # Offset column
        offset_text = Text(f"{offset:08X}", style="bold white")

        # Hex column
        hex_parts = []
        for i, b in enumerate(chunk):
            hex_str = f"{b:02X}"
            # Color non-zero, non-printable bytes differently
            if b == 0x00:
                hex_parts.append(("dim", hex_str))
            elif 32 <= b <= 126:
                hex_parts.append(("cyan", hex_str))
            else:
                hex_parts.append(("white", hex_str))

        hex_text = Text()
        for idx, (style, h) in enumerate(hex_parts):
            hex_text.append(h, style=style)
            if idx < len(hex_parts) - 1:
                hex_text.append(" ")
            if idx == 7:
                hex_text.append(" ")  # Extra space between groups of 8

        # Pad if chunk is shorter than 16
        if len(chunk) < self.BYTES_PER_ROW:
            missing = self.BYTES_PER_ROW - len(chunk)
            hex_text.append("   " * missing)

        # ASCII column
        ascii_text = Text()
        for b in chunk:
            if 32 <= b <= 126:
                ascii_text.append(chr(b), style="cyan")
            else:
                ascii_text.append(".", style="dim")

        # Assembly column
        asm_result = None
        asm_mnemonic = None
        asm_op_str = None
        for byte_off in range(offset, offset + len(chunk)):
            asm = self.disasm.get_asm_at(byte_off)
            if asm:
                asm_result = asm
                parts = asm.split(None, 1)
                asm_mnemonic = parts[0] if parts else ""
                asm_op_str = parts[1] if len(parts) > 1 else ""
                break

        # Check if this instruction matches a suspicious pattern
        threat_label = None
        if asm_mnemonic:
            for match_fn, label in SUSPICIOUS_ASM_PATTERNS:
                try:
                    if match_fn(asm_mnemonic, asm_op_str):
                        threat_label = label
                        break
                except Exception:
                    pass

        if asm_result and threat_label:
            asm_text = Text(f"{asm_result}", style="bold red")
        elif asm_result:
            asm_text = Text(f"{asm_result}", style="bold bright_green")
        else:
            asm_text = Text("")

        # Annotation column — threat label takes priority
        ann = self._get_annotation_for_row(offset)
        if threat_label:
            ann_text = Text(f"⚠ {threat_label}", style="bold red")
        elif ann:
            ann_text = Text(f"{ann.label}", style=ann.style)
        else:
            ann_text = Text("")

        return offset_text, hex_text, ascii_text, asm_text, ann_text

    def _render_page(self, page_num: int) -> Table:
        """Render a full page of hex rows as a Rich Table."""
        start_offset = page_num * self.ROWS_PER_PAGE * self.BYTES_PER_ROW
        total_pages = (len(self.data) + (self.ROWS_PER_PAGE * self.BYTES_PER_ROW) - 1) // (self.ROWS_PER_PAGE * self.BYTES_PER_ROW)

        table = Table(
            title=f"[bold]Page {page_num + 1}/{total_pages}[/]  |  [dim]{Path(self.file_path).name}  ({len(self.data):,} bytes)[/]",
            show_header=True,
            header_style="bold magenta",
            border_style="bright_black",
            pad_edge=False,
            expand=True,
        )
        table.add_column("Offset", style="bold white", width=10, no_wrap=True)
        table.add_column("Hex", min_width=49, no_wrap=True)
        table.add_column("ASCII", width=18, no_wrap=True)
        table.add_column("Assembly", style="bright_green", ratio=1, no_wrap=True)
        table.add_column("Annotation", style="yellow", ratio=1)

        for row_idx in range(self.ROWS_PER_PAGE):
            offset = start_offset + row_idx * self.BYTES_PER_ROW
            if offset >= len(self.data):
                break
            off_t, hex_t, asc_t, asm_t, ann_t = self._render_row(offset)
            table.add_row(off_t, hex_t, asc_t, asm_t, ann_t)

        return table

    def _render_summary(self) -> Panel:
        """Render a summary panel of all annotations found."""
        lines = []
        for ann in self.annotations:
            # Skip very common ones like null padding and short strings for the summary
            if "Null Padding" in ann.label:
                continue
            lines.append(f"  [{ann.style}]0x{ann.offset:08X}[/]  {ann.label}")

        if not lines:
            content = "[dim]No notable annotations found.[/]"
        else:
            # Cap at 30 lines for readability
            if len(lines) > 30:
                content = "\n".join(lines[:30]) + f"\n  [dim]... and {len(lines) - 30} more annotations[/]"
            else:
                content = "\n".join(lines)

        return Panel(
            content,
            title="[bold magenta]Annotations Summary[/]",
            border_style="magenta",
            padding=(1, 2),
        )

    def _render_cfg(self, start_offset: int, generate_insights: bool = False, max_blocks: int = 10) -> None:
        """Extract and render a CFG for the assembly starting at start_offset."""
        if not self.disasm.is_code_offset(start_offset):
            self.console.print(f"[red]Error: Offset 0x{start_offset:X} is not within a code section.[/]")
            input("\nPress Enter to continue...")
            return

        blocks = self.disasm.extract_cfg(start_offset, max_blocks=max_blocks)
        if not blocks:
            self.console.print(f"[red]No control flow graph could be extracted at 0x{start_offset:X}[/]")
            input("\nPress Enter to continue...")
            return

        insights_map: dict[int, str] = {}
        behavioral_mapping: str | None = None

        if generate_insights:
            if not hasattr(self, '_ai_engine'):
                self.console.print("[dim]Loading AI model for insights (this may take a moment)...[/]")
                self._ai_engine = ASMInsightsGenerator()

            total_steps = len(blocks)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=self.console,
                transient=True,
            ) as progress:
                task = progress.add_task(
                    "[cyan]Generating AI Assembly Insights...", total=total_steps
                )

                for block in blocks:
                    block_asm = "\n".join(
                        [f"0x{a:X}: {i}" for a, i in block.instructions]
                    )
                    try:
                        insights_map[block.id_addr] = (
                            self._ai_engine.generate_insight(block_asm)
                        )
                    except Exception as e:
                        insights_map[block.id_addr] = f"Error: {e}"
                    progress.advance(task)

        self._interactive_cfg_viewer(blocks, insights_map)

    # ── Helpers for the interactive CFG viewer ──────────────────────

    @staticmethod
    def _read_key() -> str:
        """Read a single keypress from stdin in raw mode."""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == '\x1b':  # Escape sequence (arrow keys, etc.)
                ch2 = sys.stdin.read(1)
                if ch2 == '[':
                    ch3 = sys.stdin.read(1)
                    if ch3 == 'A':
                        return 'up'
                    if ch3 == 'B':
                        return 'down'
                    if ch3 == 'C':
                        return 'right'
                    if ch3 == 'D':
                        return 'left'
                return 'escape'
            if ch == '\x03':  # Ctrl-C
                return 'q'
            if ch in ('q', 'Q'):
                return 'q'
            if ch in ('\r', '\n'):
                return 'enter'
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    @staticmethod
    def _block_has_threat(block: BasicBlock) -> bool:
        """Return True if any instruction in the block matches a suspicious pattern."""
        for _, asm in block.instructions:
            parts = asm.split(None, 1)
            mnemonic = parts[0] if parts else ""
            op_str = parts[1] if len(parts) > 1 else ""
            for match_fn, _ in SUSPICIOUS_ASM_PATTERNS:
                try:
                    if match_fn(mnemonic, op_str):
                        return True
                except Exception:
                    pass
        return False

    def _interactive_cfg_viewer(
        self,
        blocks: list[BasicBlock],
        insights_map: dict[int, str],
    ) -> None:
        """Full-screen interactive CFG viewer with arrow-key navigation."""
        selected_visual_idx = 0
        total_visual_blocks = [0]
        selected_addr = [blocks[0].id_addr if blocks else 0]
        
        block_map = {b.id_addr: b for b in blocks}
        entry_addr = blocks[0].id_addr if blocks else 0

        def _build_tree() -> Tree:
            """Build the Rich Tree with the selected block highlighted."""
            total_visual_blocks[0] = 0

            def _add_block(addr: int, tree_node: Tree, visited: set[int]) -> None:
                if addr in visited:
                    tree_node.add(f"[dim]-> Loop back to Block 0x{addr:X}[/]")
                    return
                if addr not in block_map:
                    tree_node.add(f"[dim]-> External/Unknown: 0x{addr:X}[/]")
                    return

                visited.add(addr)
                block = block_map[addr]
                
                is_selected = (total_visual_blocks[0] == selected_visual_idx)
                if is_selected:
                    selected_addr[0] = addr
                    
                total_visual_blocks[0] += 1
                
                has_threat = HexViewer._block_has_threat(block)

                # Build instruction text
                insn_lines = []
                for i_addr, asm in block.instructions:
                    threat = None
                    parts = asm.split(None, 1)
                    mnemonic = parts[0] if parts else ""
                    op_str = parts[1] if len(parts) > 1 else ""
                    for match_fn, threat_label in SUSPICIOUS_ASM_PATTERNS:
                        try:
                            if match_fn(mnemonic, op_str):
                                threat = threat_label
                                break
                        except Exception:
                            pass
                    if threat:
                        insn_lines.append(
                            f"[red]0x{i_addr:X}: {asm:<30} [!] {threat}[/]"
                        )
                    else:
                        insn_lines.append(f"[cyan]0x{i_addr:X}:[/] {asm}")

                insn_text = "\n".join(insn_lines)

                # Highlight selected block
                if is_selected:
                    border = "bold yellow"
                    title = f"[bold yellow]> Block 0x{addr:X}[/]"
                elif has_threat:
                    border = "red"
                    title = f"[bold red]Block 0x{addr:X} [!][/]"
                else:
                    border = "magenta"
                    title = f"[bold magenta]Block 0x{addr:X}[/]"

                panel = Panel(
                    insn_text, title=title, border_style=border, expand=False
                )
                node = tree_node.add(panel)

                # Add successor edges
                for succ in block.successors:
                    if len(block.successors) > 1:
                        if succ == block.successors[0]:
                            edge_label = "[bold red]False (Fallthrough) ->[/]"
                        else:
                            edge_label = "[bold green]True (Jump) ->[/]"
                    else:
                        edge_label = "[bold blue]->[/]"
                    child_branch = node.add(edge_label)
                    _add_block(succ, child_branch, visited.copy())

            root = Tree(
                f"[bold cyan]Control Flow Graph (Entry: 0x{entry_addr:X})[/]"
            )
            _add_block(entry_addr, root, set())
            return root

        def _build_detail_panel() -> Panel:
            """Build the detail panel for the currently selected block."""
            block = block_map.get(selected_addr[0], blocks[0])
            detail = Text()

            for i_addr, asm in block.instructions:
                threat = None
                parts = asm.split(None, 1)
                mnemonic = parts[0] if parts else ""
                op_str = parts[1] if len(parts) > 1 else ""
                for match_fn, threat_label in SUSPICIOUS_ASM_PATTERNS:
                    try:
                        if match_fn(mnemonic, op_str):
                            threat = threat_label
                            break
                    except Exception:
                        pass

                if threat:
                    detail.append(
                        f"  0x{i_addr:X}: {asm:<30} [!] {threat}\n",
                        style="bold red",
                    )
                else:
                    detail.append(f"  0x{i_addr:X}: ", style="white")
                    detail.append(f"{asm}\n", style="bright_green")

            # Successors
            detail.append("\n")
            detail.append("  Successors: ", style="bold white")
            if block.successors:
                for succ in block.successors:
                    detail.append(f"0x{succ:X} ", style="yellow")
            else:
                detail.append("none (terminal)", style="dim")
            detail.append("\n")

            # AI Insight
            insight = insights_map.get(block.id_addr)
            if insight:
                detail.append("\n")
                detail.append("  AI Insight\n", style="bold green")
                for line in insight.split("\n"):
                    detail.append(f"  {line}\n", style="italic green")

            has_threat = HexViewer._block_has_threat(block)
            detail_title = f"[bold magenta]Block 0x{block.id_addr:X}[/]"
            if has_threat:
                detail_title += " [bold red][!] SUSPICIOUS[/]"
            return Panel(
                detail,
                title=detail_title,
                border_style="magenta",
                padding=(1, 1),
            )

        def _build_layout() -> Layout:
            layout = Layout()
            layout.split_row(
                Layout(name="graph", ratio=3, minimum_size=45),
                Layout(name="detail", ratio=2, minimum_size=35),
            )

            # Build and capture the tree
            tree = _build_tree()
            # Calculate actual width based on the 3:2 ratio (60%) minus padding
            term_w = max(45, int(self.console.width * 0.6) - 4)
            dummy_console = Console(
                width=term_w,
                color_system=self.console.color_system,
                force_terminal=True,
                highlight=False,
            )
            with dummy_console.capture() as cap:
                dummy_console.print(tree)
            tree_out = cap.get()
            
            lines = tree_out.split("\n")
            
            # Find selected line
            selected_idx = 0
            for i, line in enumerate(lines):
                if "> Block" in line:
                    selected_idx = i
                    break
                    
            # Window the lines to fit the terminal height
            term_h = self.console.height - 4
            visible_count = max(5, term_h)
            half = visible_count // 2
            
            # Apply extra_scroll and clamp
            desired_start = selected_idx - half + extra_scroll[0]
            start = max(0, min(desired_start, len(lines) - visible_count))
            
            # Update extra_scroll to reflect the clamped physical bounds (prevents dead scrolling)
            extra_scroll[0] = start - (selected_idx - half)
            
            end = min(len(lines), start + visible_count)
            if end == len(lines):
                start = max(0, end - visible_count)
                
            visible_lines = lines[start:end]
            
            # Add scroll indicators if needed
            from rich.text import Text
            renderables = []
            if start > 0:
                renderables.append(Text(f"  ^ scrolled down {start} lines", style="dim italic"))
            renderables.append(Text.from_ansi("\n".join(visible_lines)))
            if end < len(lines):
                renderables.append(Text(f"  v {len(lines) - end} more lines below", style="dim italic"))
                
            graph_panel = Panel(
                Group(*renderables),
                title="[bold]Control Flow Graph[/]",
                subtitle=f"[dim]↑/↓ Navigate  |  q Quit  |  [{selected_visual_idx + 1}/{max(1, total_visual_blocks[0])}][/]",
                border_style="cyan",
                padding=(0, 1),
            )
            layout["graph"].update(graph_panel)
            layout["detail"].update(_build_detail_panel())
            
            return layout

        # ── Interactive loop ──
        extra_scroll = [0]
        with Live(
            _build_layout(),
            console=self.console,
            screen=True,
            auto_refresh=False,
        ) as live:
            while True:
                key = self._read_key()
                if key == 'q':
                    break
                elif key == 'up':
                    if extra_scroll[0] > 0:
                        extra_scroll[0] -= 1
                    elif selected_visual_idx > 0:
                        selected_visual_idx -= 1
                        extra_scroll[0] = 0
                    else:
                        extra_scroll[0] -= 1
                elif key == 'down':
                    if extra_scroll[0] < 0:
                        extra_scroll[0] += 1
                    elif selected_visual_idx < total_visual_blocks[0] - 1:
                        selected_visual_idx += 1
                        extra_scroll[0] = 0
                    else:
                        extra_scroll[0] += 1
                else:
                    continue
                live.update(_build_layout(), refresh=True)

    def run(self) -> None:
        """Launch the interactive paginated hex viewer."""
        total_pages = max(1, (len(self.data) + (self.ROWS_PER_PAGE * self.BYTES_PER_ROW) - 1) // (self.ROWS_PER_PAGE * self.BYTES_PER_ROW))
        page = 0

        kb = KeyBindings()
        
        @kb.add("left")
        def _(event):
            b = event.app.current_buffer
            b.text = "p"
            b.validate_and_handle()
            
        @kb.add("right")
        def _(event):
            b = event.app.current_buffer
            b.text = "n"
            b.validate_and_handle()
            
        session = PromptSession(key_bindings=kb)

        # Banner
        self.console.print("\n[bold cyan]  Binary Research Mode[/]\n", justify="center")

        # Show annotation summary first
        self.console.print(self._render_summary())
        self.console.print()

        # Controls help
        self.console.print(
            Panel(
                "[bold]Enter / Right Arrow[/] → Next page  |  [bold]p / Left Arrow[/] → Previous page  |  "
                "[bold]g <num>[/] → Go to page  |  [bold]s <num>[/] → Jump to offset\n"
                "[bold]a[/] → Show annotations  |  [bold]c[/] / [bold]c <num>[/] → Show CFG  |  [bold]q[/] → Quit",
                title="[bold]Controls[/]",
                border_style="bright_black",
            )
        )


        run = True
        while run:
            self.console.print()
            self.console.print(self._render_page(page))
            self.console.print()

            try:
                cmd = session.prompt(f"[Page {page + 1}/{total_pages}] > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                self.console.print("\n[bold]Exiting research mode.[/]")
                run = False

            if cmd == "q" or cmd == "quit":
                self.console.print("[bold]Exiting research mode.[/]")
                run = False
            elif cmd == "" or cmd == "n":
                # Next page
                if page < total_pages - 1:
                    page += 1
                else:
                    self.console.print("[yellow]Already at last page.[/]")
            elif cmd == "p":
                # Previous page
                if page > 0:
                    page -= 1
                else:
                    self.console.print("[yellow]Already at first page.[/]")
            elif cmd.startswith("g ") or cmd.startswith("g"):
                # Go to page
                try:
                    target = cmd.split(maxsplit=1)
                    if len(target) > 1:
                        target_page = int(target[1]) - 1
                    else:
                        target_page = int(input("Go to page: ")) - 1
                    if 0 <= target_page < total_pages:
                        page = target_page
                    else:
                        self.console.print(f"[red]Invalid page. Valid range: 1-{total_pages}[/]")
                except ValueError:
                    self.console.print("[red]Enter a valid page number.[/]")
            elif cmd == "s" or cmd.startswith("s "):
                # Jump to offset
                try:
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        offset_str = parts[1]
                    else:
                        offset_str = input("Offset (hex, e.g. 0x80): ")
                    target_offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                    target_page = target_offset // (self.ROWS_PER_PAGE * self.BYTES_PER_ROW)
                    if 0 <= target_page < total_pages:
                        page = target_page
                        self.console.print(f"[green]Jumped to offset 0x{target_offset:X} (page {page + 1})[/]")
                    else:
                        self.console.print(f"[red]Offset 0x{target_offset:X} is beyond file size.[/]")
                except ValueError:
                    self.console.print("[red]Enter a valid offset (decimal or 0xHEX).[/]")
            elif cmd == "a":
                # Show annotations summary again
                self.console.print(self._render_summary())
            elif cmd == "c" or cmd.startswith("c "):
                # Extract and render CFG
                try:
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        offset_str = parts[1]
                        target_offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                    else:
                        # Find the first executable code byte on the current page
                        target_offset = None
                        start_offset = page * self.ROWS_PER_PAGE * self.BYTES_PER_ROW
                        end_offset = start_offset + (self.ROWS_PER_PAGE * self.BYTES_PER_ROW)
                        for off in range(start_offset, end_offset):
                            if self.disasm.is_code_offset(off):
                                target_offset = off
                                break
                        if target_offset is None:
                            self.console.print("[red]No executable code found on current page to graph. Supply an offset: c <offset>[/]")
                            continue
                            
                    # Ask for AI Insights
                    try:
                        ans = session.prompt("Generate AI insights for this graph? (y/n) > ").strip().lower()
                        gen_insights = ans in ("y", "yes")
                    except (EOFError, KeyboardInterrupt):
                        gen_insights = False

                    self._render_cfg(target_offset, generate_insights=gen_insights, max_blocks=1000)
                except ValueError:
                    self.console.print("[red]Enter a valid offset (decimal or 0xHEX).[/]")
            else:
                self.console.print("[dim]Unknown command. Press Enter for next page, 'q' to quit.[/]")
