# 🕵🏻‍♂️ ClearFake - Detecting Win+R command runs
---
## Description
This query looks through DeviceRegistryEvents and more specifically, changes to the RunMRU registry, which logs all commands and inputs to the Windows "Run" prompt accessible through Win + R. Running commands through Win+R is a common attack vector of ClickFix malware, where it is usually camouflaged as a "captcha-check".

Even though this is titled as a ClearFake detection, this query can be used to detect other types of ClickFix malware as well.

### References
- [PaloAlto Unit 42 - Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)

## Defender XDR
```KQL
// Searching for Win+R run prompt events from the registry
DeviceRegistryEvents
//| where DeviceId == '' // Scope to specific device if needed
| where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
| where ActionType == "RegistryValueSet"
| where RegistryValueName != "MRUList"
| project Timestamp, DeviceId, DeviceName, PromptRun = RegistryValueData
| order by Timestamp desc

```

