rule AMTS_d7273bb969450fbe
{
    meta:
        author = "AMTS-Engine"
        date = "2026-11-26T21:16:31Z"
        sha256 = "d7273bb969450fbe3173e938a8ae7fedf3d53983d0d04e3d6d80e9c4c3a2c17f"
        description = "Auto-generated YARA rule for sample d7273bb969450fbe"
        packed_sections = "none"
        emulation_performed = "false"
        high_fidelity_indicators = "8"
        medium_fidelity_indicators = "0"

    strings:
        $s0 = "http://malware-c2.example.com/beacon"
        $s1 = "VirtualAllocEx"
        $s2 = "CreateRemoteThread"
        $s3 = "WriteProcessMemory"
        $s4 = "URLDownloadToFileA"
        $s5 = "AdjustTokenPrivileges"
        $s6 = "192.168.100.5"
        $s7 = "evil.tk"

    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}
