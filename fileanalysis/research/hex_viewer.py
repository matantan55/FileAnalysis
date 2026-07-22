
"""Interactive hex viewer with binary annotations for file research."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

import capstone
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.columns import Columns


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


# ─── Disassembler Helper ───────────────────────────────────────────

class Disassembler:
    """Detects architecture from binary headers and disassembles code sections."""

    def __init__(self, data: bytes):
        self.data = data
        self.arch = None
        self.mode = None
        self.md = None
        # code_sections: list of (file_offset, size) for executable sections
        self.code_sections: list[tuple[int, int]] = []
        # Precomputed: file_offset → assembly string
        self._asm_cache: dict[int, str] = {}

        self._detect_and_init()

    def _detect_and_init(self) -> None:
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
            self._disassemble_sections()

    def _disassemble_sections(self) -> None:
        """Pre-disassemble all code sections and cache by file offset."""
        if not self.md:
            return
        for sec_offset, sec_size in self.code_sections:
            code = self.data[sec_offset:sec_offset + sec_size]
            for insn in self.md.disasm(code, sec_offset):
                self._asm_cache[insn.address] = f"{insn.mnemonic} {insn.op_str}".strip()

    def get_asm_at(self, offset: int) -> str | None:
        """Return the assembly instruction at the given file offset, or None."""
        return self._asm_cache.get(offset)

    def is_code_offset(self, offset: int) -> bool:
        """Check if an offset falls within a code section."""
        for sec_off, sec_size in self.code_sections:
            if sec_off <= offset < sec_off + sec_size:
                return True
        return False


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
        self.console.print("[dim]Disassembling code sections...[/]")
        self.disasm = Disassembler(self.data)
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

    def run(self) -> None:
        """Launch the interactive paginated hex viewer."""
        import pyfiglet

        total_pages = max(1, (len(self.data) + (self.ROWS_PER_PAGE * self.BYTES_PER_ROW) - 1) // (self.ROWS_PER_PAGE * self.BYTES_PER_ROW))
        page = 0

        # Banner
        banner = pyfiglet.figlet_format("ThreatNet", font="slant")
        self.console.print(f"[bold red]\n{banner}[/]", justify="center")
        self.console.print("[bold cyan]  Binary Research Mode[/]\n", justify="center")

        # Show annotation summary first
        self.console.print(self._render_summary())
        self.console.print()

        # Controls help
        self.console.print(
            Panel(
                "[bold]Enter[/] → Next page  |  [bold]p[/] → Previous page  |  "
                "[bold]g <num>[/] → Go to page  |  [bold]s[/] → Jump to offset  |  "
                "[bold]a[/] → Show annotations  |  [bold]q[/] → Quit",
                title="[bold]Controls[/]",
                border_style="bright_black",
            )
        )

        while True:
            self.console.print()
            self.console.print(self._render_page(page))
            self.console.print()

            try:
                cmd = input(f"[Page {page + 1}/{total_pages}] > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                self.console.print("\n[bold]Exiting research mode.[/]")
                break

            if cmd == "q" or cmd == "quit":
                self.console.print("[bold]Exiting research mode.[/]")
                break
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
            else:
                self.console.print("[dim]Unknown command. Press Enter for next page, 'q' to quit.[/]")
