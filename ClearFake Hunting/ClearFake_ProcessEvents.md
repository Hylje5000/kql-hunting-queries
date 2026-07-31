# 🦞 ClearFake - Detecting malicious runs
---
## Description
This query looks through DeviceProcessEvents from Defender for Endpoint, looking for processes or command line executions usual to ClickFix attacks like ClearFake. 

### References
- [PaloAlto Unit 42 - Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Kroll - Rapid evolution of CLEARFAKE delivery](https://www.kroll.com/en/publications/cyber/rapid-evolution-of-clearfake-delivery)

## Defender XDR
```KQL
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("explorer.exe", "WmiPrvSE.exe", "pcalua.exe")
| where
    // structural: env-var split + FOR-loop indirect execution (ClearFake evasion trick)
    (ProcessCommandLine matches regex @"for\s+%\w+\s+in\s*\(.*\)\s+do\s+@%\w+")
    or
    // structural: WebDAV over SSL UNC path
    (ProcessCommandLine has @"@SSL\")
    or
    // structural: rundll32/regsvr32-style ordinal call on a disguised file
    (ProcessCommandLine matches regex @",#\d+")
    or
    // known keyword fallback for unobfuscated variants
    (ProcessCommandLine has_any (
        "mshta", "Win32_Process", "IEX", "Invoke-Expression", "DownloadString",
        "-enc", "-EncodedCommand", "-w hidden", "-windowstyle hidden",
        "saps ", "pushd", "certutil -urlcache", "bitsadmin /transfer"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

