import math
import re
from datetime import datetime, timezone

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

HIGH_FIDELITY_APIS = {
    "VirtualAllocEx", "VirtualProtectEx",
    "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
    "WriteProcessMemory", "NtWriteVirtualMemory",
    "ShellExecuteA", "ShellExecuteExA",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
    "InternetConnectA", "InternetConnectW", "HttpOpenRequestA", "HttpSendRequestA",
    "WSAStartup",
    "RegSetValueExA", "RegCreateKeyExA",
    "LoadLibraryA", "LoadLibraryExA",
    "CryptEncrypt", "CryptDecrypt",
    "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "AdjustTokenPrivileges",
    "SetWindowsHookExA", "SetWindowsHookExW",
    "WinExec",
}

MEDIUM_FIDELITY_APIS = {
    "VirtualAlloc", "VirtualProtect",
    "OpenProcess",
    "CreateProcessA", "CreateProcessW",
    "ShellExecuteW", "ShellExecuteExW",
    "InternetOpenW", "InternetOpenUrlW",
    "InternetConnectW", "HttpSendRequestA",
    "RegSetValueExW", "RegCreateKeyExW",
    "RegDeleteKeyA", "RegDeleteValueA",
    "LoadLibraryW",
    "CryptCreateHash", "CryptHashData",
    "IsDebuggerPresent",
    "GetTickCount", "QueryPerformanceCounter",
    "LookupPrivilegeValueA",
    "CreateThread",
    "ReadProcessMemory",
}

COMMON_APIS = {
    "CreateFileA", "CreateFileW", "WriteFile", "ReadFile",
    "DeleteFileA", "DeleteFileW", "MoveFileA", "CopyFileA",
    "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
    "socket", "connect", "send", "recv", "bind", "listen", "accept",
    "HeapAlloc", "HeapFree", "LocalAlloc", "GlobalAlloc",
    "OpenProcess",
}

IP_STANDALONE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
DOMAIN_STANDALONE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|info|biz|ru|cn|tk|top|xyz|pw|cc|ws|io|me|co)$"
)
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]{8,}")

ARCH_MAP = {
    0x14c: "x86 (i386)",
    0x8664: "x86-64 (AMD64)",
    0x1c0: "ARM",
    0xaa64: "ARM64",
    0x200: "IA-64 (Itanium)",
}

GENERIC_NOISE = {
    "This program cannot be run in DOS mode",
    "!This program cannot be run in DOS mode",
    "VS_VERSION_INFO", "VarFileInfo", "StringFileInfo",
    "Translation", "CompanyName", "FileDescription",
    "FileVersion", "InternalName", "LegalCopyright",
    "OriginalFilename", "ProductName", "ProductVersion",
    "Assembly Version", "PADDING", "Rich",
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss",
    ".pdata", ".didat", ".tls", ".CRT", ".edata", ".idata",
}


def calculate_shannon_entropy(data):
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def extract_ascii_strings(data, min_length=6):
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    return [match.decode("ascii", errors="ignore") for match in pattern.findall(data)]


def extract_unicode_strings(data, min_length=6):
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    results = []
    for match in pattern.findall(data):
        try:
            decoded = match.decode("utf-16-le").strip("\x00")
            if len(decoded) >= min_length:
                results.append(decoded)
        except (UnicodeDecodeError, ValueError):
            continue
    return results


def classify_api(name):
    if name in HIGH_FIDELITY_APIS:
        return "high"
    if name in MEDIUM_FIDELITY_APIS:
        return "medium"
    return None


def filter_suspicious_strings(strings):
    suspicious = []
    seen = set()

    for s in strings:
        stripped = s.strip()
        if stripped in seen or len(stripped) < 4 or stripped in GENERIC_NOISE:
            continue
        seen.add(stripped)

        api_tier = classify_api(stripped)
        if api_tier == "high":
            suspicious.append({"value": stripped, "type": "suspicious_api", "fidelity": "high"})
        elif api_tier == "medium":
            suspicious.append({"value": stripped, "type": "suspicious_api", "fidelity": "medium"})
        elif URL_PATTERN.search(stripped):
            suspicious.append({"value": stripped, "type": "url", "fidelity": "high"})
        elif IP_STANDALONE.match(stripped):
            suspicious.append({"value": stripped, "type": "ip_address", "fidelity": "high"})
        elif DOMAIN_STANDALONE.match(stripped):
            suspicious.append({"value": stripped, "type": "domain", "fidelity": "high"})

    return suspicious


def analyze(file_path, entropy_threshold=7.2):
    if not PEFILE_AVAILABLE:
        return {
            "error": "pefile library is not installed",
            "imphash": None,
            "sections": [],
            "suspicious_strings": [],
            "compilation_timestamp": None,
            "architecture": None,
            "section_count": 0,
        }

    result = {
        "imphash": None,
        "sections": [],
        "suspicious_strings": [],
        "compilation_timestamp": None,
        "architecture": None,
        "section_count": 0,
    }

    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        result["error"] = "Invalid PE file format"
        return result

    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
        result["compilation_timestamp"] = datetime.fromtimestamp(
            timestamp, tz=timezone.utc
        ).isoformat()
    except (ValueError, OSError, OverflowError):
        result["compilation_timestamp"] = f"raw:{pe.FILE_HEADER.TimeDateStamp}"

    machine = pe.FILE_HEADER.Machine
    result["architecture"] = ARCH_MAP.get(machine, f"Unknown (0x{machine:04x})")
    result["section_count"] = pe.FILE_HEADER.NumberOfSections

    try:
        result["imphash"] = pe.get_imphash()
    except Exception:
        result["imphash"] = None

    for section in pe.sections:
        try:
            name = section.Name.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            name = "unknown"
        data = section.get_data()
        entropy = calculate_shannon_entropy(data)
        result["sections"].append({
            "name": name,
            "entropy": entropy,
            "is_packed": entropy >= entropy_threshold,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
        })

    with open(file_path, "rb") as f:
        raw_data = f.read()
    ascii_strings = extract_ascii_strings(raw_data)
    unicode_strings = extract_unicode_strings(raw_data)
    all_strings = ascii_strings + unicode_strings
    result["suspicious_strings"] = filter_suspicious_strings(all_strings)

    pe.close()
    return result
