# OpenClaw - Detecting usage
---
## Description
This query looks through DeviceProcessEvents from Defender for Endpoint, looking for processes or command line executions related to openclaw / clawdbot / moltbot and it's common forks. OpenClaw isn't something that should be ran on your company network or company-owned devices, so you can use this to detect it. Queries are based on official Microsoft queries shared as a part of their blog post.

### References
- [Microsoft Defender Security Research Team - Running OpenClaw safely: identity, isolation, and runtime risk](https://www.microsoft.com/en-us/security/blog/2026/02/19/running-openclaw-safely-identity-isolation-runtime-risk/)

## Defender XDR
```KQL
DeviceProcessEvents 
| where Timestamp > ago(30d) 
| where ProcessCommandLine has_any ("openclaw","moltbot","clawdbot", "nanoclaw", "zeroclaw", "clawhub") 
   or FileName has_any ("openclaw","moltbot","clawdbot", "nanoclaw", "zeroclaw", "clawhub") 
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, ProcessCommandLine 
| order by Timestamp desc
```



