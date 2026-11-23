# Clean Samples Directory

This directory is used by the YARA rule validation engine to test generated rules
against known-clean Windows system files. The goal is to ensure that synthesized
rules do not produce false positive matches on legitimate binaries.

## How to Populate

Copy a selection of standard Windows PE executables into this directory. Good
candidates include:

- C:\Windows\System32\calc.exe
- C:\Windows\System32\notepad.exe
- C:\Windows\System32\write.exe
- C:\Windows\System32\mspaint.exe
- C:\Windows\System32\charmap.exe
- C:\Windows\System32\cmd.exe
- C:\Windows\System32\taskmgr.exe
- C:\Windows\System32\winver.exe

You can copy them using PowerShell:

```powershell
$targets = @("calc.exe", "notepad.exe", "write.exe", "mspaint.exe", "cmd.exe", "taskmgr.exe", "winver.exe")
foreach ($t in $targets) {
    $src = "C:\Windows\System32\$t"
    if (Test-Path $src) {
        Copy-Item $src -Destination ".\clean_samples\"
    }
}
```

The more clean files you provide, the more robust the false positive detection
becomes. A minimum of 10 files is recommended.

## Important Notes

- Only PE format files (.exe, .dll, .sys) should be placed here.
- Do not place any malicious files in this directory.
- The README.md file is automatically excluded from scanning.
