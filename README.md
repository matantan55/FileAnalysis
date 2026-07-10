# FileAnalysis CLI Tool

A CLI-based static file analysis and malware threat assessment tool written in Python. It analyzes PE, DLL, ELF, Mach-O binaries, scripts, and documents to identify potential threats, mapped capabilities, and environmental impacts.

## Installation

Install using `uv` or `pip`:

```bash
pip install -e .
```

Or install all dependencies explicitly:

```bash
pip install -r requirements.txt
```

## Usage

Run the analysis tool against any file:

```bash
fileanalysis scan path/to/file
```

### Options

- `--vt`: Perform optional VirusTotal API lookup on the file hash.
- `--vt-api-key KEY`: Provide your VirusTotal API Key.
- `--json`: Output full analysis report in JSON format.
- `--yara-rules DIR`: Path to a custom directory containing YARA rules.
