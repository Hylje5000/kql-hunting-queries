# WPS Office - Detect processes through DeviceProcessEvents
---
## Description
This quite simple hunting query is for detecting processes on endpoints where keywords match to known WPS Office / Kingsoft strings. WPS Office is a pesky chinese freeware Office clone that installs itself into the user context without need for admin credentials, leading to many users installing it without even realizing, while not showing up on app registries like Defender for Endpoint / Intune. It is also known to act a lot like malware, with some components being matched on VirusTotal.

## Defender XDR
```KQL
DeviceProcessEvents 
| where Timestamp > ago(14d) 
| where ProcessCommandLine has_any ("WPS", "WPS Office", "Kingsoft") or FileName has_any ("WPS", "WPS Office", "Kingsoft")
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, AccountUpn, InitiatingProcessCommandLine
```



