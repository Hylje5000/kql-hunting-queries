# 🗂️ WPS Office - Phone Home connections listing
---
## Description
This hunting query can be used to list IP Addresses / Domains that WPS Office connects to. WPS Office is a pesky chinese freeware Office clone that installs itself into the user context without need for admin credentials, leading to many users installing it without even realizing, while not showing up on app registries like Defender for Endpoint / Intune. This hunting query also includes geolocation info for the logs, letting you see how much data you are sending to China 😉

## Defender XDR
```KQL
DeviceEvents
| where FolderPath contains "Kingsoft"

DeviceNetworkEvents
| where InitiatingProcessFolderPath contains "Kingsoft"
| project TimeGenerated, RemoteUrl, InitiatingProcessFileName, InitiatingProcessVersionInfoProductName, InitiatingProcessCommandLine

DeviceNetworkEvents
| where InitiatingProcessFolderPath contains "Kingsoft"
| where isnotempty(RemoteIP)
// Filter out private IPs
| where RemoteIP !startswith "10."
    and RemoteIP !startswith "192.168."
    and RemoteIP !startswith "172."
    and RemoteIP != "127.0.0.1"
| extend GeoInfo = geo_info_from_ip_address(RemoteIP)
| extend
    Country = tostring(GeoInfo.country),
    City    = tostring(GeoInfo.city)
| summarize
    ConnectionCount  = count(),
    FirstSeen        = min(TimeGenerated),
    LastSeen         = max(TimeGenerated),
    Devices          = dcount(DeviceName),
    RemoteUrls       = make_set(RemoteUrl, 20),
    ProcessNames     = make_set(InitiatingProcessFileName, 10)
    by RemoteIP, Country, City
| sort by ConnectionCount desc
```