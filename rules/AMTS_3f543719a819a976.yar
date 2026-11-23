rule AMTS_3f543719a819a976
{
    meta:
        author = "AMTS-Engine"
        date = "2026-08-26T04:32:13Z"
        sha256 = "3f543719a819a9769d8f138a02544f93af8b53ef1779a96bc2403715d9a55380"
        description = "Auto-generated YARA rule for sample 3f543719a819a976"
        packed_sections = "none"
        emulation_performed = "false"

    strings:
        $imphash = { aa 9e 7e 1b d3 5e 47 c6 de 05 df 96 02 41 a9 86 }
        $s0 = "ShellExecuteW"
        $s1 = "GetProcAddress"
        $s2 = "IsDebuggerPresent"
        $s3 = "CreateFileW"
        $s4 = "WriteFile"
        $s5 = "DeleteFileW"
        $s6 = "RegSetValueExW"
        $s7 = "RegCreateKeyExW"
        $s8 = "CreateProcessW"
        $s9 = "QueryPerformanceCounter"
        $s10 = "    version=\"5.1.0.0\""
        $s11 = "            version=\"6.0.0.0\""
        $s12 = "    <windowsSettings xmlns:ws2=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">"
        $s13 = "https://go.microsoft.com/fwlink/?LinkId=834783"
        $s14 = "https://go.microsoft.com/fwlink/p/?linkid=838060"

    condition:
        uint16(0) == 0x5A4D and ($imphash or 3 of ($s*))
}
