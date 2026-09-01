"""Model Context Protocol (MCP) server for FileAnalysis.

Exposes MalOwn's analysis pipeline and binary research tools to
AI agents over stdio (local) or SSE (remote) transports.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Route
import uvicorn

from fileanalysis.pipeline import run_pipeline
from fileanalysis.reporting.json_report import JsonReporter
from fileanalysis.research.hex_viewer import BinaryAnnotator, Disassembler

logger = logging.getLogger("malown.mcp")

app = Server("MalOwn")


# ── Helpers ──────────────────────────────────────────────────────────

def _validate_file_path(file_path: str) -> Path:
    """Resolve and validate a file path.

    Raises:
        FileNotFoundError: If the path does not exist.
        ValueError: If the path is not a regular file.
    """
    resolved = Path(file_path).resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"File not found: {resolved}")
    if not resolved.is_file():
        raise ValueError(f"Not a regular file: {resolved}")
    return resolved


def _error_response(message: str) -> list[types.TextContent]:
    """Return an MCP error response."""
    return [types.TextContent(type="text", text=json.dumps({"error": message}))]


# ── Tool Definitions ─────────────────────────────────────────────────

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    """Return the list of tools exposed by this MCP server."""
    return [
        types.Tool(
            name="analyze_file",
            description=(
                "Run the full MalOwn scanning pipeline on a file. "
                "Returns a JSON report containing hashes, entropy, "
                "YARA matches, MITRE ATT&CK capabilities, and "
                "ensemble threat scores (heuristic + neural net + LightGBM)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the file to analyze.",
                    },
                    "yara_rules": {
                        "type": "string",
                        "description": (
                            "Optional path to a directory containing custom "
                            "YARA rule files (.yar/.yara)."
                        ),
                    },
                },
                "required": ["file_path"],
            },
        ),
        types.Tool(
            name="get_binary_annotations",
            description=(
                "Extract suspicious byte patterns, file headers, "
                "and API strings from a binary file."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the binary file.",
                    },
                },
                "required": ["file_path"],
            },
        ),
        types.Tool(
            name="extract_control_flow_graph",
            description=(
                "Extract the intra-procedural control flow graph "
                "(basic blocks and disassembled instructions) starting "
                "at a given file offset."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the binary file.",
                    },
                    "start_offset": {
                        "type": "integer",
                        "description": "Byte offset in the file where disassembly begins.",
                    },
                    "is_rva": {
                        "type": "boolean",
                        "description": "Set to true if start_offset is a Relative Virtual Address (RVA) (e.g. from an entry point) so it can be resolved to a file offset.",
                        "default": False,
                    },
                },
                "required": ["file_path", "start_offset"],
            },
        ),
        types.Tool(
            name="get_hex_dump",
            description=(
                "Return a raw hex dump with ASCII representation "
                "for a byte region of a file."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the file.",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Byte offset to start the dump from.",
                    },
                    "size": {
                        "type": "integer",
                        "description": "Number of bytes to dump (default: 512).",
                        "default": 512,
                    },
                },
                "required": ["file_path", "offset"],
            },
        ),
    ]


# ── Tool Router ──────────────────────────────────────────────────────

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    """Route an incoming tool call to the correct handler."""
    logger.info("Tool '%s' called with arguments: %s", name, arguments)

    try:
        if name == "analyze_file":
            return _handle_analyze_file(arguments)
        elif name == "get_binary_annotations":
            return _handle_get_binary_annotations(arguments)
        elif name == "extract_control_flow_graph":
            return _handle_extract_control_flow_graph(arguments)
        elif name == "get_hex_dump":
            return _handle_get_hex_dump(arguments)
        else:
            logger.warning("Unknown tool requested: %s", name)
            return _error_response(f"Unknown tool: {name}")
    except FileNotFoundError as exc:
        logger.error("File not found: %s", exc)
        return _error_response(str(exc))
    except ValueError as exc:
        logger.error("Validation error: %s", exc)
        return _error_response(str(exc))
    except Exception as exc:
        logger.exception("Unhandled error in tool '%s'", name)
        return _error_response(f"Internal error: {exc}")


# ── Tool Handlers ────────────────────────────────────────────────────

def _handle_analyze_file(arguments: dict) -> list[types.TextContent]:
    """Run the full analysis pipeline on a file."""
    path = _validate_file_path(arguments["file_path"])
    yara_rules = arguments.get("yara_rules")

    result = run_pipeline(str(path), yara_rules)
    report_json = JsonReporter().render(result)

    logger.info(
        "Analysis complete: %s — score=%.1f (%s)",
        path.name,
        result.ensemble_score,
        result.ensemble_risk_level.value,
    )
    return [types.TextContent(type="text", text=report_json)]


def _handle_get_binary_annotations(arguments: dict) -> list[types.TextContent]:
    """Extract binary annotations from a file."""
    path = _validate_file_path(arguments["file_path"])
    data = path.read_bytes()

    annotator = BinaryAnnotator()
    annotations = annotator.annotate(data)

    output = [
        {
            "offset": a.offset,
            "length": a.length,
            "label": a.label,
            "style": a.style,
        }
        for a in annotations
    ]
    return [types.TextContent(type="text", text=json.dumps(output))]


def _rva_to_file_offset(rva: int, pe) -> int | None:
    """Resolve an RVA to a file offset using the PE section table."""
    for sec in pe.sections:
        va_start = sec.VirtualAddress
        # max() guards against packers/compilers that leave virtual_size at 0
        va_end = va_start + max(sec.Misc_VirtualSize, sec.SizeOfRawData)

        if va_start <= rva < va_end:
            delta = rva - va_start
            if delta >= sec.SizeOfRawData:
                # RVA points into zero-padded tail (e.g. .bss) - no file bytes here
                return None
            return sec.PointerToRawData + delta
    return None


def _handle_extract_control_flow_graph(arguments: dict) -> list[types.TextContent]:
    """Extract the CFG at a given offset."""
    path = _validate_file_path(arguments["file_path"])
    start_offset = arguments["start_offset"]
    is_rva = arguments.get("is_rva", False)
    data = path.read_bytes()

    if is_rva:
        try:
            import pefile
            pe = pefile.PE(data=data)
            resolved = _rva_to_file_offset(start_offset, pe)
            if resolved is None:
                return _error_response(f"RVA 0x{start_offset:X} could not be resolved to a file bytes offset (it may be in a .bss section or invalid).")
            logger.info("Resolved RVA 0x%X to file offset 0x%X", start_offset, resolved)
            start_offset = resolved
        except Exception as e:
            logger.warning("Failed to parse PE for RVA resolution: %s", e)
            # Fall back to trying it as a raw offset

    disasm = Disassembler(data)
    blocks = disasm.extract_cfg(start_offset)

    output = [
        {
            "id_addr": b.id_addr,
            "instructions": [
                {"address": addr, "asm": asm} for addr, asm in b.instructions
            ],
            "successors": b.successors,
        }
        for b in blocks
    ]
    return [types.TextContent(type="text", text=json.dumps(output))]


def _handle_get_hex_dump(arguments: dict) -> list[types.TextContent]:
    """Generate a hex dump for a file region."""
    path = _validate_file_path(arguments["file_path"])
    offset = arguments["offset"]
    size = arguments.get("size", 512)

    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read(size)

    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_str = " ".join(f"{b:02X}" for b in chunk).ljust(47)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        current_offset = offset + i
        lines.append(f"{current_offset:08X}  {hex_str}  |{ascii_str}|")

    return [types.TextContent(type="text", text="\n".join(lines))]


# ── Transport: stdio ─────────────────────────────────────────────────

async def _run_stdio() -> None:
    """Run the MCP server over standard I/O."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


# ── Transport: SSE ───────────────────────────────────────────────────

def _run_sse(host: str, port: int) -> None:
    """Run the MCP server over HTTP Server-Sent Events."""
    sse = SseServerTransport("/messages")

    async def handle_sse(request):
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await app.run(
                streams[0], streams[1], app.create_initialization_options()
            )

    async def handle_messages(request):
        await sse.handle_post_message(
            request.scope, request.receive, request._send
        )

    starlette_app = Starlette(
        debug=False,
        routes=[
            Route("/sse", endpoint=handle_sse),
            Route("/messages", endpoint=handle_messages, methods=["POST"]),
        ],
    )

    logger.info("Starting SSE server on %s:%d", host, port)
    uvicorn.run(starlette_app, host=host, port=port)


# ── Entry Point ──────────────────────────────────────────────────────

def main() -> None:
    """CLI entry point for the MCP server."""
    parser = argparse.ArgumentParser(
        description="MalOwn MCP Server — expose analysis tools to AI agents."
    )
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "sse"],
        help="Transport type (default: stdio).",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind the SSE server to (default: 0.0.0.0).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for the SSE server (default: 8000).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO).",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if args.transport == "stdio":
        asyncio.run(_run_stdio())
    else:
        _run_sse(args.host, args.port)


if __name__ == "__main__":
    main()
