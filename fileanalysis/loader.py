"""File loading, type detection, and routing to appropriate analyzers."""

from __future__ import annotations

import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

import puremagic

from fileanalysis.analyzers.base import AnalysisResult, FileMetadata


# Maximum file size: 100 MB
MAX_FILE_SIZE = 100 * 1024 * 1024

# Magic byte signatures for file type detection
MAGIC_SIGNATURES: dict[bytes, str] = {
    b"MZ": "pe",
    b"\x7fELF": "elf",
    b"\xfe\xed\xfa\xce": "macho",   # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf": "macho",   # Mach-O 64-bit
    b"\xce\xfa\xed\xfe": "macho",   # Mach-O 32-bit reversed
    b"\xcf\xfa\xed\xfe": "macho",   # Mach-O 64-bit reversed
    b"\xca\xfe\xba\xbe": "macho",   # Mach-O universal
    b"%PDF": "pdf",
    b"\xd0\xcf\x11\xe0": "ole",     # OLE compound (Office docs)
    b"PK\x03\x04": "zip",           # ZIP (also OOXML docs, JAR)
}

# Script shebangs and extensions
SCRIPT_EXTENSIONS = {
    ".py", ".pyw",        # Python
    ".ps1", ".psm1",      # PowerShell
    ".sh", ".bash",       # Bash/Shell
    ".js", ".mjs",        # JavaScript
    ".vbs", ".vbe",       # VBScript
    ".bat", ".cmd",       # Windows Batch
    ".rb",                # Ruby
    ".pl",                # Perl
    ".php",               # PHP
}

DOCUMENT_EXTENSIONS = {
    ".doc", ".docx", ".docm",
    ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm",
    ".pdf",
    ".rtf",
}


def _humanize_size(size_bytes: int) -> str:
    """Convert byte count to human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:,.1f} {unit}"
        size_bytes /= 1024  # type: ignore[assignment]
    return f"{size_bytes:,.1f} TB"


def _format_timestamp(ts: float) -> str:
    """Format a Unix timestamp to ISO format."""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, ValueError, OverflowError):
        return "N/A"


def _get_permissions(file_path: str) -> str:
    """Get file permissions as a string (e.g., 'rwxr-xr-x')."""
    try:
        st = os.stat(file_path)
        mode = st.st_mode
        perms = ""
        for who in ("USR", "GRP", "OTH"):
            for what, letter in (("R", "r"), ("W", "w"), ("X", "x")):
                flag = getattr(stat, f"S_I{what}{who}")
                perms += letter if mode & flag else "-"
        return perms
    except OSError:
        return "N/A"


def _detect_file_type(file_bytes: bytes, file_path: str) -> tuple[str, str]:
    """Detect file type from magic bytes and extension.

    Returns:
        Tuple of (file_type, description).
        file_type is one of: pe, elf, macho, script, document, pdf, ole, zip, unknown
    """
    # Check magic bytes first
    for sig, ftype in MAGIC_SIGNATURES.items():
        if file_bytes[:len(sig)] == sig:
            # For PE files, determine if it's DLL or EXE
            if ftype == "pe":
                desc = "Windows PE executable"
                # Quick check for DLL characteristic flag
                if len(file_bytes) > 0x3C + 4:
                    try:
                        pe_offset = int.from_bytes(file_bytes[0x3C:0x40], "little")
                        if len(file_bytes) > pe_offset + 0x16 + 2:
                            characteristics = int.from_bytes(
                                file_bytes[pe_offset + 0x16:pe_offset + 0x18], "little"
                            )
                            if characteristics & 0x2000:  # IMAGE_FILE_DLL
                                desc = "Windows DLL (Dynamic Link Library)"
                    except (ValueError, IndexError):
                        pass
                return ftype, desc
            elif ftype == "elf":
                return ftype, "Linux ELF binary"
            elif ftype == "macho":
                return ftype, "macOS Mach-O binary"
            elif ftype == "pdf":
                return "document", "PDF document"
            elif ftype == "ole":
                return "document", "OLE compound document (Microsoft Office)"
            elif ftype == "zip":
                # Check if it's an OOXML document
                ext = Path(file_path).suffix.lower()
                if ext in DOCUMENT_EXTENSIONS:
                    return "document", f"OOXML document ({ext})"
                return "zip", "ZIP archive"

    # Check extension for scripts
    ext = Path(file_path).suffix.lower()
    if ext in SCRIPT_EXTENSIONS:
        return "script", f"Script file ({ext})"

    # Check shebang for scripts
    if file_bytes[:2] == b"#!":
        try:
            first_line = file_bytes[:256].split(b"\n")[0].decode("utf-8", errors="replace")
            return "script", f"Script file (shebang: {first_line.strip()})"
        except Exception:
            return "script", "Script file (shebang detected)"

    # Check extension for documents
    if ext in DOCUMENT_EXTENSIONS:
        return "document", f"Document ({ext})"

    # Try to detect if it's a text file
    try:
        sample = file_bytes[:8192]
        # Check for high ratio of printable chars
        printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
        if len(sample) > 0 and printable / len(sample) > 0.85:
            return "text", "Text file"
    except Exception:
        pass

    return "unknown", "Unknown file type"


def _get_magic_description(file_path: str) -> str:
    """Get detailed file type description using puremagic."""
    try:
        matches = puremagic.magic_file(file_path)
        if matches:
            best_match = matches[0]
            return f"{best_match.name} ({best_match.mime_type})"
    except Exception:
        pass
    return ""


def load_file(file_path: str) -> tuple[bytes, AnalysisResult]:
    """Load a file and prepare the initial AnalysisResult.

    Args:
        file_path: Path to the file to analyze.

    Returns:
        Tuple of (file_bytes, initial AnalysisResult).

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the file exceeds the size limit.
        PermissionError: If the file can't be read.
    """
    path = Path(file_path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Not a regular file: {file_path}")

    file_size = path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise ValueError(
            f"File too large: {_humanize_size(file_size)} "
            f"(max: {_humanize_size(MAX_FILE_SIZE)})"
        )

    if file_size == 0:
        raise ValueError("File is empty (0 bytes)")

    file_bytes = path.read_bytes()

    file_type, type_desc = _detect_file_type(file_bytes, str(path))
    magic_desc = _get_magic_description(str(path))

    st = path.stat()

    metadata = FileMetadata(
        name=path.name,
        path=str(path),
        size=file_size,
        size_human=_humanize_size(file_size),
        mime_type="",
        file_type=file_type,
        magic_description=magic_desc or type_desc,
        creation_time=_format_timestamp(st.st_ctime),
        modification_time=_format_timestamp(st.st_mtime),
        permissions=_get_permissions(str(path)),
    )

    result = AnalysisResult(metadata=metadata)

    return file_bytes, result
