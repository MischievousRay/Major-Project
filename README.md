# AMTS-Engine

Automated Malware Triage and Dynamic YARA Rule Synthesis Engine

## Overview

AMTS-Engine is a web-based malware analysis platform that automates the process of
triaging Windows PE executables, performing static and dynamic analysis, and
synthesizing production-ready YARA detection rules. The system operates as a
continuous pipeline that accepts file uploads through a web interface, processes
them through parallel analysis stages, generates detection signatures, validates
them against known-clean files, and presents the results through an interactive
threat report dashboard.

## Architecture

The engine is structured as a five-phase pipeline:

```
                                +-------------------+
                                |   Web Dashboard   |
                                |  (Upload / View)  |
                                +--------+----------+
                                         |
                                         v
                                +-------------------+
                                |   Ingestion API   |
                                | SHA-256, MZ Check |
                                +--------+----------+
                                         |
                         +---------------+----------------+
                         |                                |
                         v                                v
              +---------------------+         +---------------------+
              | Static Decomposition|         | OS Emulation        |
              | (PE Headers, Entropy|         | (speakeasy-emulator)|
              |  Strings, ImpHash)  |         | (API Hooking, Behav)|
              +----------+----------+         +----------+----------+
                         |                                |
                         +---------------+----------------+
                                         |
                                         v
                                +-------------------+
                                | Aggregation Router|
                                +--------+----------+
                                         |
                                         v
                                +-------------------+
                                | Rule Synthesis    |
                                | (YARA Generation) |
                                +--------+----------+
                                         |
                                         v
                                +-------------------+
                                | Validation Engine |
                                | (FP Elimination)  |
                                +--------+----------+
                                         |
                                         v
                                +-------------------+
                                | SQLite Database   |
                                | + Rule File (.yar)|
                                +-------------------+
```

## System Requirements

- Python 3.9 or later
- pip package manager
- Windows, Linux, or macOS (Windows recommended for full PE emulation support)

### Required Python Packages

| Package | Purpose |
|---|---|
| Flask | Web framework and REST API |
| Flask-SQLAlchemy | ORM and database management |
| pefile | PE binary parsing and analysis |
| yara-python | YARA rule compilation and matching |
| speakeasy-emulator | Dynamic binary emulation (optional) |
| Werkzeug | HTTP utilities and file handling |

## Installation

### 1. Clone or Download the Project

```bash
cd /path/to/your/workspace
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

Activate it:

- Windows: `venv\Scripts\activate`
- Linux/macOS: `source venv/bin/activate`

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

Note: `yara-python` requires a C compiler on some systems. On Windows, you may
need to install Visual C++ Build Tools. Alternatively, use a prebuilt wheel:

```bash
pip install yara-python
```

Note: `speakeasy-emulator` is optional. If it is not installed or fails to
initialize, the engine will skip the dynamic emulation phase and complete the
pipeline with static analysis results only. The generated YARA rule will be
based solely on static indicators in that case.

### 4. Populate Clean Samples (Recommended)

Copy known-clean Windows PE files into the `clean_samples/` directory. These are
used by the validation engine to test generated YARA rules for false positives.
See `clean_samples/README.md` for detailed instructions.

```powershell
Copy-Item C:\Windows\System32\notepad.exe .\clean_samples\
Copy-Item C:\Windows\System32\calc.exe .\clean_samples\
Copy-Item C:\Windows\System32\cmd.exe .\clean_samples\
```

### 5. Run the Application

```bash
python run.py
```

The server starts at `http://127.0.0.1:5000` by default.

## Usage

### Web Dashboard

1. Open `http://127.0.0.1:5000` in your browser.
2. Drag and drop a Windows PE executable (.exe, .dll, .sys) onto the upload zone,
   or click to browse files.
3. The file is validated (MZ header check) and queued for analysis.
4. The dashboard displays the job status, which transitions from QUEUED to
   EXECUTING to COMPLETED.
5. Click "View Report" to see the full threat analysis, including:
   - File metadata (SHA-256, architecture, compilation timestamp)
   - Section entropy analysis with visual bar chart
   - Suspicious string extraction (IPs, domains, URLs, API calls)
   - Dynamic behavior timeline (if emulation was successful)
   - Generated YARA rule with validation status
6. Download the YARA rule as a `.yar` file or copy it to clipboard.

### REST API

All functionality is available through the REST API for integration with
external tools and automation scripts.

#### Upload a File

```
POST /api/upload
Content-Type: multipart/form-data
```

Request body: multipart form data with a `file` field containing the PE binary.

Response (202 Accepted):
```json
{
    "job_id": "aB3kM9xQ7nWp",
    "filename": "sample.exe",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "status": "QUEUED",
    "file_path": "/path/to/uploads/e3b0c44298fc...",
    "duplicate": false
}
```

If the file has already been analyzed (matching SHA-256), the response returns
the existing job with `"duplicate": true` and status 200.

If the file does not have a valid MZ header, the response returns status 422
with an error message.

#### Check Job Status

```
GET /api/status/<job_id>
```

Response:
```json
{
    "job_id": "aB3kM9xQ7nWp",
    "filename": "sample.exe",
    "sha256": "e3b0c44298fc...",
    "status": "COMPLETED",
    "created_at": "2025-01-15T10:30:00",
    "completed_at": "2025-01-15T10:30:25"
}
```

Status values: `QUEUED`, `EXECUTING`, `COMPLETED`, `FAILED`.

#### Get Full Report

```
GET /api/report/<job_id>
```

Returns a JSON object containing all analysis results:

```json
{
    "job_id": "aB3kM9xQ7nWp",
    "filename": "sample.exe",
    "sha256": "e3b0c44298fc...",
    "status": "COMPLETED",
    "static_analysis": {
        "imphash": "d4a0e3c5b2f1a8e7...",
        "compilation_timestamp": "2024-03-15T08:22:00+00:00",
        "architecture": "x86 (i386)",
        "section_count": 5,
        "sections": [
            {
                "name": ".text",
                "entropy": 6.4521,
                "is_packed": false,
                "virtual_size": 32768,
                "raw_size": 32768
            },
            {
                "name": ".rsrc",
                "entropy": 7.8912,
                "is_packed": true,
                "virtual_size": 65536,
                "raw_size": 65536
            }
        ],
        "suspicious_strings": [
            {"value": "192.168.1.100", "type": "ip_address"},
            {"value": "malware-c2.evil.com", "type": "domain"},
            {"value": "CreateRemoteThread", "type": "suspicious_api"}
        ]
    },
    "dynamic_analysis": {
        "behaviors": [
            {
                "elapsed_ms": 150,
                "function": "kernel32.CreateRemoteThread",
                "arguments": {"arg_0": "0x1234", "arg_1": "0x5678"},
                "severity": "Code Injection"
            }
        ],
        "emulation_success": true,
        "error_message": null
    },
    "yara_rule": {
        "rule_name": "AMTS_e3b0c44298fc1c14",
        "rule_text": "rule AMTS_e3b0c44298fc1c14 { ... }",
        "validation_status": "PASSED",
        "false_positive_count": 0
    }
}
```

#### Download YARA Rule

```
GET /api/rules/<job_id>
```

Returns the raw YARA rule text as a downloadable `.yar` file.

#### List Recent Jobs

```
GET /api/jobs
```

Returns an array of the 50 most recent jobs.

## Pipeline Phase Details

### Phase 1: Ingestion

The ingestion API receives the uploaded file through an HTTP multipart form
request. It buffers the file in memory and computes a SHA-256 hash. The system
checks the database for this hash. If it already exists, the pipeline stops and
returns the existing report to avoid redundant processing. If the hash is new,
the engine reads the first two bytes of the file and verifies they match the
hexadecimal values 0x4D and 0x5A (the standard Windows MZ executable signature).
Valid files are saved to the `uploads/` directory using their hash as the
filename, and a unique 12-character alphanumeric job identifier is assigned.

### Phase 2: Static Decomposition

The engine opens the saved binary and parses its PE headers using the pefile
library. It extracts:

- **Compilation Timestamp**: The date the binary was compiled, from the PE
  COFF header.
- **Target Architecture**: CPU architecture (x86, x86-64, ARM, ARM64) from
  the Machine field.
- **Section Count**: Number of PE sections.
- **Import Hash (ImpHash)**: An MD5 fingerprint of the binary's import table,
  created by hashing the lowercase names of all imported DLLs and functions.
  This fingerprint identifies families of malware that share the same software
  dependencies.
- **Section Entropy**: Shannon entropy is calculated for each section of the
  binary. The formula measures byte distribution randomness on a scale of 0.0
  to 8.0. Sections scoring 7.2 or higher are flagged as potentially packed or
  encrypted, since legitimate code typically has entropy between 5.0 and 7.0.
- **String Extraction**: The engine scans the entire binary for continuous
  sequences of ASCII and Unicode characters (minimum 4 characters). Extracted
  strings are filtered against regular expressions for IP addresses, domain
  names, URLs, and a list of over 50 known suspicious Windows API function
  names associated with process injection, network communication, registry
  modification, anti-analysis, and cryptographic operations.

### Phase 3: Dynamic Emulation

The engine uses the speakeasy-emulator framework (by Mandiant) to emulate the
binary in a simulated 64-bit Windows environment. Speakeasy creates fake
registry paths, files, and memory spaces. It loads the binary into virtual
memory and places monitoring hooks on critical system libraries including
kernel32.dll, advapi32.dll, and ws2_32.dll. The binary is executed from its
entry point with a configurable timeout (default: 20 seconds).

Every intercepted API call is recorded with:
- Elapsed milliseconds since execution started
- The library and function name (e.g., kernel32.CreateRemoteThread)
- A key-value map of the function arguments
- A severity category assigned by the behavior classifier

Severity categories include:
- **Code Injection**: CreateRemoteThread, WriteProcessMemory, VirtualAllocEx
- **Network Beaconing**: InternetOpenA, URLDownloadToFileA, socket, connect
- **Registry Modification**: RegSetValueExA, RegCreateKeyExA
- **Process Creation**: CreateProcessA, WinExec, ShellExecuteA
- **File Manipulation**: CreateFileA, WriteFile, DeleteFileA
- **Anti-Analysis**: IsDebuggerPresent, GetTickCount
- **Privilege Escalation**: AdjustTokenPrivileges
- **Cryptographic Activity**: CryptEncrypt, CryptDecrypt

If speakeasy is not installed or the emulation fails (e.g., unsupported binary
format), the pipeline continues with static analysis results only. The report
notes the emulation skip reason.

### Phase 4: Rule Synthesis

The engine combines the unique strings, import hash, and behavioral indicators
collected from the previous phases. It filters strings to remove generic PE
labels (e.g., .text, .data, .rdata, PADDING, VS_VERSION_INFO) and retains only
high-fidelity indicators such as IP addresses, domain names, URLs, and
suspicious API names.

It generates a YARA rule with the following structure:

- **meta**: SHA-256 hash, author ("AMTS-Engine"), generation timestamp,
  description, packed section list, and emulation status.
- **strings**: The import hash as a hex pattern, and each filtered string as
  a named variable ($s0, $s1, etc.).
- **condition**: A boolean expression requiring the file to have a valid MZ
  header (`uint16(0) == 0x5A4D`) combined with either the exact import hash
  match or a minimum count of the extracted unique strings (configurable
  threshold, default: 3).

### Phase 5: Validation

The engine compiles the generated YARA rule using yara-python and scans it
against all files in the `clean_samples/` directory. This directory should
contain at least 10 known-clean Windows system files (e.g., notepad.exe,
calc.exe, cmd.exe).

If the rule matches any clean file (a false positive), the engine identifies
the specific string that caused the match, removes it from the rule, adjusts
the condition threshold, and re-runs the validation scan. This iterative
refinement continues for up to 10 rounds until the rule produces zero matches
on the clean file set.

If the rule passes validation, it is marked as PASSED and saved as a `.yar`
file in the `rules/` directory. The complete analysis data and final rule are
stored in the SQLite database.

## Configuration

The application is configured through `config.py`. Key settings:

| Setting | Default | Description |
|---|---|---|
| MAX_CONTENT_LENGTH | 16 MB | Maximum upload file size |
| ENTROPY_PACKING_THRESHOLD | 7.2 | Entropy score above which a section is flagged as packed |
| EMULATION_TIMEOUT_SECONDS | 20 | Maximum emulation duration in seconds |
| EMULATION_MAX_INSTRUCTIONS | 1,000,000 | Maximum CPU instructions to emulate |
| MIN_STRING_LENGTH | 4 | Minimum character length for extracted strings |
| YARA_STRING_MATCH_THRESHOLD | 3 | Number of strings required to match in the YARA condition |
| UPLOAD_FOLDER | ./uploads | Directory for stored samples |
| CLEAN_SAMPLES_DIR | ./clean_samples | Directory of known-clean files for validation |
| RULES_OUTPUT_DIR | ./rules | Directory for generated YARA rule files |

## Project Structure

```
Major Project/
    config.py                   Application configuration
    run.py                      Flask entry point
    requirements.txt            Python dependencies
    amts_engine.db              SQLite database (auto-created)
    app/
        __init__.py             Flask app factory
        models.py               SQLAlchemy database models
        routes/
            __init__.py
            api.py              REST API endpoints
            dashboard.py        Web dashboard routes
        engine/
            __init__.py
            ingestion.py        SHA-256 hashing, MZ validation, file storage
            static_analysis.py  PE parsing, entropy, imphash, string extraction
            emulation.py        Speakeasy-based dynamic analysis
            rule_synthesis.py   YARA rule generation
            validation.py       False positive testing and remediation
            pipeline.py         Analysis pipeline orchestrator
        templates/
            base.html           Base layout template
            index.html          Upload and dashboard page
            report.html         Threat analysis report page
        static/
            css/
                style.css       Dark-mode UI stylesheet
            js/
                app.js          Client-side upload and polling logic
    clean_samples/
        README.md               Setup instructions for clean validation files
    uploads/                    Stored sample binaries (by SHA-256 hash)
    rules/                      Generated YARA rule files (.yar)
```

## Database Schema

The application uses SQLite with four tables:

- **jobs**: Core job tracking with id, filename, sha256, status, file_path,
  created_at, and completed_at fields.
- **static_results**: Static analysis output linked to a job. Stores imphash,
  compilation timestamp, architecture, section count, and JSON-encoded section
  details and suspicious strings.
- **dynamic_results**: Dynamic analysis output linked to a job. Stores
  JSON-encoded behavior log, emulation success flag, and error messages.
- **yara_rules**: Generated YARA rules linked to a job. Stores rule name, full
  rule text, validation status, and false positive count.

## Troubleshooting

### yara-python installation fails

On Windows, install Visual C++ Build Tools first, or use a prebuilt wheel:
```bash
pip install yara-python
```

On Linux:
```bash
sudo apt-get install -y libyara-dev
pip install yara-python
```

### speakeasy-emulator not working

Speakeasy requires the Unicorn engine. If installation fails:
```bash
pip install unicorn
pip install speakeasy-emulator
```

The engine is designed to work without speakeasy. If it is not installed, the
pipeline completes with static analysis only and notes the skip in the report.

### Empty entropy chart or no sections

This usually means the uploaded file is not a valid PE executable. The engine
only processes files with a valid MZ header (first two bytes: 0x4D 0x5A).

### YARA rule validation shows "PASSED_NO_SAMPLES"

This means the `clean_samples/` directory is empty. Populate it with clean
Windows PE files to enable false positive detection. See
`clean_samples/README.md` for instructions.

### Database reset

To reset the database and start fresh, delete the `amts_engine.db` file and
restart the application. The database will be recreated automatically.

## Limitations

- The emulation engine (speakeasy) simulates a subset of the Windows API. Some
  advanced malware techniques that rely on unsupported APIs may not be captured.
- YARA rule quality depends on the distinctiveness of the analyzed sample.
  Heavily packed or obfuscated binaries may produce rules with fewer indicators.
- The validation phase can only detect false positives against the files present
  in the clean_samples directory. A larger and more diverse set of clean files
  improves validation coverage.
- The application uses threading for parallel analysis, which is suitable for
  development and moderate workloads. For high-throughput production use, a
  dedicated task queue (e.g., Celery) is recommended.

## License

This project is developed for academic purposes.
