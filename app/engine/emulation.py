import time
import traceback

try:
    import speakeasy as se
    SPEAKEASY_AVAILABLE = True
except ImportError:
    SPEAKEASY_AVAILABLE = False

SEVERITY_MAP = {
    "CreateRemoteThread": "Code Injection",
    "NtCreateThreadEx": "Code Injection",
    "RtlCreateUserThread": "Code Injection",
    "WriteProcessMemory": "Code Injection",
    "NtWriteVirtualMemory": "Code Injection",
    "VirtualAllocEx": "Code Injection",
    "VirtualProtectEx": "Code Injection",
    "CreateProcessA": "Process Creation",
    "CreateProcessW": "Process Creation",
    "WinExec": "Process Creation",
    "ShellExecuteA": "Process Creation",
    "ShellExecuteW": "Process Creation",
    "ShellExecuteExA": "Process Creation",
    "ShellExecuteExW": "Process Creation",
    "InternetOpenA": "Network Beaconing",
    "InternetOpenW": "Network Beaconing",
    "InternetOpenUrlA": "Network Beaconing",
    "InternetOpenUrlW": "Network Beaconing",
    "InternetConnectA": "Network Beaconing",
    "InternetConnectW": "Network Beaconing",
    "HttpOpenRequestA": "Network Beaconing",
    "HttpSendRequestA": "Network Beaconing",
    "URLDownloadToFileA": "Network Beaconing",
    "URLDownloadToFileW": "Network Beaconing",
    "WSAStartup": "Network Beaconing",
    "socket": "Network Beaconing",
    "connect": "Network Beaconing",
    "send": "Network Beaconing",
    "recv": "Network Beaconing",
    "RegSetValueExA": "Registry Modification",
    "RegSetValueExW": "Registry Modification",
    "RegCreateKeyExA": "Registry Modification",
    "RegCreateKeyExW": "Registry Modification",
    "RegDeleteKeyA": "Registry Modification",
    "RegDeleteValueA": "Registry Modification",
    "CreateFileA": "File Manipulation",
    "CreateFileW": "File Manipulation",
    "WriteFile": "File Manipulation",
    "DeleteFileA": "File Manipulation",
    "DeleteFileW": "File Manipulation",
    "MoveFileA": "File Manipulation",
    "CopyFileA": "File Manipulation",
    "VirtualAlloc": "Memory Allocation",
    "VirtualProtect": "Memory Modification",
    "GetProcAddress": "Dynamic Resolution",
    "LoadLibraryA": "Dynamic Resolution",
    "LoadLibraryW": "Dynamic Resolution",
    "LoadLibraryExA": "Dynamic Resolution",
    "CryptEncrypt": "Cryptographic Activity",
    "CryptDecrypt": "Cryptographic Activity",
    "CryptCreateHash": "Cryptographic Activity",
    "CryptHashData": "Cryptographic Activity",
    "IsDebuggerPresent": "Anti-Analysis",
    "CheckRemoteDebuggerPresent": "Anti-Analysis",
    "NtQueryInformationProcess": "Anti-Analysis",
    "GetTickCount": "Anti-Analysis",
    "QueryPerformanceCounter": "Anti-Analysis",
    "AdjustTokenPrivileges": "Privilege Escalation",
    "LookupPrivilegeValueA": "Privilege Escalation",
    "SetWindowsHookExA": "Input Capture",
    "SetWindowsHookExW": "Input Capture",
}


def classify_behavior(api_name):
    return SEVERITY_MAP.get(api_name, "General API Call")


def parse_speakeasy_report(report):
    behaviors = []
    if not report:
        return behaviors

    entries = report.get("entry_points", [])
    for ep in entries:
        api_calls = ep.get("apis", [])
        for call in api_calls:
            api_name = call.get("api_name", "")
            args = call.get("args", [])
            ret_val = call.get("ret_val", None)

            arg_map = {}
            for i, arg in enumerate(args):
                arg_map[f"arg_{i}"] = str(arg) if arg is not None else "null"

            if ret_val is not None:
                arg_map["return_value"] = str(ret_val)

            lib = call.get("module", "unknown")
            behaviors.append({
                "elapsed_ms": call.get("time", 0),
                "function": f"{lib}.{api_name}",
                "arguments": arg_map,
                "severity": classify_behavior(api_name),
            })

    network_events = report.get("network_events", {})
    dns_queries = network_events.get("dns", [])
    for dns in dns_queries:
        behaviors.append({
            "elapsed_ms": 0,
            "function": "dns.resolve",
            "arguments": {"hostname": dns.get("hostname", "unknown")},
            "severity": "Network Beaconing",
        })

    http_requests = network_events.get("traffic", [])
    for req in http_requests:
        behaviors.append({
            "elapsed_ms": 0,
            "function": "network.connection",
            "arguments": {
                "server": req.get("server", ""),
                "port": str(req.get("port", "")),
                "type": req.get("type", ""),
            },
            "severity": "Network Beaconing",
        })

    return behaviors


def emulate(file_path, timeout=20, max_instructions=1_000_000):
    if not SPEAKEASY_AVAILABLE:
        return {
            "behaviors": [],
            "emulation_success": False,
            "error_message": "speakeasy-emulator is not installed. Install it with: pip install speakeasy-emulator",
        }

    try:
        emu = se.Speakeasy()
        module = emu.load_module(file_path)
        emu.run_module(module, timeout=timeout)
        report = emu.get_report()
        behaviors = parse_speakeasy_report(report)

        return {
            "behaviors": behaviors,
            "emulation_success": True,
            "error_message": None,
        }
    except Exception as e:
        return {
            "behaviors": [],
            "emulation_success": False,
            "error_message": f"Emulation failed: {str(e)}",
        }
