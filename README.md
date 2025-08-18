# AppLocker Inspector

```
    _                _               _               ___                           _             
   / \   _ __  _ __ | |    ___   ___| | _____ _ __  |_ _|_ __  ___ _ __   ___  ___| |_ ___  _ __ 
  / _ \ | '_ \| '_ \| |   / _ \ / __| |/ / _ \ '__|  | || '_ \/ __| '_ \ / _ \/ __| __/ _ \| '__|
 / ___ \| |_) | |_) | |__| (_) | (__|   <  __/ |     | || | | \__ \ |_) |  __/ (__| || (_) | |   
/_/   \_\ .__/| .__/|_____\___/ \___|_|\_\___|_|    |___|_| |_|___/ .__/ \___|\___|\__\___/|_|   
        |_|   |_|                                                 |_|                            
		By: Spencer Alessi (@techspence)
```

AppLocker Inspector audits an AppLocker policy XML and reports weak/misconfigured/risky settings, including actual ACL checks. If you don’t provide a policy file, the tool will **export the local effective AppLocker policy** and analyze that automatically.



## Features

- **Policy acquisition**
  - If `-Path` is omitted, collects the **local effective** policy via `Get-AppLockerPolicy -Effective -Xml`, saves it to disk, and audits it.
- **Collection posture checks**
  - Flags `NotConfigured` and `AuditOnly` collections (EXE, DLL, Script, MSI, Packaged app).
- **Rule risk detection**
  - Broad principals: **Everyone / Authenticated Users / BUILTIN\Users**.
  - Overly broad **path** rules (drive roots, user-writable trees, wildcards, UNC).
  - **Publisher** rules allowing *any product/binary* or with *no upper version bound*.
  - **Hash** rules assigned to broad principals.
- **Real-world permission validation**
  - **Local NTFS** rights checked with `Get-Acl` on referenced paths.
  - **UNC** paths: optional **share ACL** read (CIM/WMI via `Get-SmbShareAccess` or `Win32_LogicalShareSecuritySetting`) plus **NTFS** on the UNC target itself.
- **Smarter severity**
  - Broad principal + **protected, read-only locations** (e.g., `Program Files`, `Windows` but **not** `Windows\Temp`) are downgraded to **Info** to avoid false positives.
- **Actionable findings**
  - Structured output with **Severity, Reason, Recommendation**, tied to the exact **Rule/Condition**.



## Requirements

- **PowerShell:** Windows PowerShell **5.1+** (compatible) or PowerShell **7.x**.
- **OS:** Windows 10/11 or Windows Server with AppLocker available.
- **Permissions:**
  - Exporting **effective policy** typically requires **elevated PowerShell**.
  - Reading **remote share ACLs** requires appropriate rights on the file server and open firewall for CIM/WMI/SMB.



## Installation

Save the script as `Invoke-AppLockerInspector.ps1`. You can dot-source it or call it directly.

```powershell
# From the folder where you saved it
. .\Invoke-AppLockerInspector.ps1     # dot-source once per session

# Or call directly as a script file
powershell -ExecutionPolicy Bypass -File .\Invoke-AppLockerInspector.ps1
