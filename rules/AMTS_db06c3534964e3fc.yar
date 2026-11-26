rule AMTS_db06c3534964e3fc
{
    meta:
        author = "AMTS-Engine"
        date = "2026-11-26T21:55:02Z"
        sha256 = "db06c3534964e3fc79d2763144ba53742d7fa250ca336f4a0fe724b75aaff386"
        description = "Auto-generated YARA rule for sample db06c3534964e3fc"
        packed_sections = "none"
        emulation_performed = "true"
        high_fidelity_indicators = "3"
        medium_fidelity_indicators = "10"

    strings:
        $imphash = { d0 05 85 44 e4 58 8b 1b 22 90 b7 f4 d8 30 eb 0a }
        $s0 = "NtQueryInformationProcess"
        $s1 = "LoadLibraryExA"
        $s2 = "<dpiAware  xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>"
        $s3 = "IsDebuggerPresent"
        $s4 = "ShellExecuteExW"

    condition:
        uint16(0) == 0x5A4D and ($imphash or 3 of ($s*))
}
