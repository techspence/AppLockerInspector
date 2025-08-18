<img width="500" height="500" alt="AppLocker INSPECTOR" src="https://github.com/user-attachments/assets/b14b6796-d1ef-47a8-aff2-ad6b4bb9c5e1" />

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
# dot-source from the folder where you saved it
. .\Invoke-AppLockerInspector.ps1

# Or call directly as a script file
powershell -ExecutionPolicy Bypass -File .\Invoke-AppLockerInspector.ps1
```

## Quick Start

```powershell
# Audit the local effective policy (no arguments)
# Exports %TEMP%\AppLockerPolicy-<COMPUTERNAME>-yyyyMMdd-HHmmss.xml and audits it.
Invoke-AppLockerInspector -Verbose | Format-Table -Auto

# Save the exported policy to a specific path
Invoke-AppLockerInspector -OutPolicyXml C:\Reports\Effective-AppLocker.xml -Verbose

# Audit a specific XML export
Invoke-AppLockerInspector -Path .\applocker.xml

# Include UNC share permission checks
# Use current credentials
Invoke-AppLockerInspector -Path .\applocker.xml -TestSharePermissions

# Use alternate credentials for remote servers
Invoke-AppLockerInspector -Path .\applocker.xml -TestSharePermissions -Credential (Get-Credential)

# Export findings
# CSV
Invoke-AppLockerInspector -Path .\applocker.xml -OutCsv .\findings.csv

# JSON
Invoke-AppLockerInspector -Path .\applocker.xml -AsJson | Out-File .\findings.json -Encoding utf8
```

| Parameter | Type | Description |
|---------- | ---- | ----------- | 
| `Path` | `string` | Path to an AppLocker XML export. **If omitted**, the tool calls `Get-AppLockerPolicy -Effective -Xml`, saves it, and audits that. |
| `OutPolicyXml` | `string` | Where to save the generated effective policy when `-Path` is omitted. Default: `%TEMP%\AppLockerPolicy-<COMPUTERNAME>-yyyyMMdd-HHmmss.xml`. |
| `TestSharePermissions` | `switch` | Check **share ACLs** for UNC paths (and **NTFS** on the UNC target). Requires rights/connectivity to file servers. |
| `Credential` | `PSCredential` | Credentials for remote share ACL queries when `-TestSharePermissions` is used. |
| `AsJson`     | `switch` | Output findings as JSON. |
| `OutCsv`     | `string` | Export findings to CSV. |

## Example output

| Severity | Collection | RuleType          | Action | Principal           | RuleName                    | ConditionType | Condition                                                                            | Reason                                                                                                            | Recommendation                                                                                                        |
| -------: | ---------- | ----------------- | :----: | ------------------- | --------------------------- | ------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
|     High | EXE        | FilePathRule      |  Allow | Everyone            | Temp EXEs                   | Path          | `C:\Users\*\AppData\Local\Temp\*.exe`                                                | User profile/AppData is writable; Principal is broad; Wildcard extension pattern (`*.exe`).                       | Avoid user-writable paths; replace with Publisher/Hash rules limited to required binaries.                            |
|     High | DLL        | (collection)      |   n/a  | n/a                 | n/a                         | n/a           | n/a                                                                                  | Collection 'DLL' is NotConfigured → default-allow for this type.                                                  | Set EnforcementMode=`Enabled` for DLL (or `AuditOnly` during pilot).                                                  |
|     High | EXE        | FilePathRule      |  Allow | Authenticated Users | Corp Share Tools            | Path          | `\\filesrv01\tools\updater.exe`                                                      | Share ACL on `\\filesrv01\tools` grants Change/Full to broad principals.                                          | Tighten SMB share ACL; remove Change/Full for broad groups; restrict to a minimal, purpose-built group.               |
|   Medium | Script     | FilePathRule      |  Allow | Authenticated Users | Org Scripts                 | Path          | `\\filesrv01\scripts\*.ps1`                                                          | Wildcard path; parent `\\filesrv01\scripts` NTFS grants Modify to broad principals.                               | Avoid wildcard allows on writable trees; constrain by exact files or trusted publisher and harden NTFS on the parent. |
|   Medium | EXE        | FilePublisherRule |  Allow | Authenticated Users | Vendor Any                  | Publisher     | `Publisher='O=Contoso, L=Redmond'; Product='*'; Binary='*'; VersionRange=[1.0.*, *]` | Any product and any binary from the publisher are allowed; No upper version bound; Principal is broad.            | Constrain to specific Product/Binary and set an upper version bound; reduce principal scope.                          |
|     Info | Script     | FilePathRule      |  Allow | Everyone            | CreateTeamsFirewallRule.ps1 | Path          | `C:\Program Files\Acme\Scripts\CreateTeamsFirewallRule.ps1`                          | Broad principal allowed, but target is in a protected location and not writable by broad principals (NTFS: Read). | No change needed if file remains locked down; consider Publisher/Hash for defense-in-depth.                           |


## Risk Scoring (Simplified)

### High
- Broad principals can **Write/Modify/Full** to a referenced path (local or UNC).
- Collection is **NotConfigured** or **AuditOnly**.
- Execution allowed from user-writable areas, drive roots, or unsafe wildcards.

### Medium
- Wildcards with a **parent directory** that’s writable by broad groups.
- Publisher rules too broad (e.g., `Product='*'` and `Binary='*'`; no upper version).

### Low
- Allow-by-hash given to broad principals (rule is tight, group is broad).

### Info
- Broad principal but target is **protected & read-only** (`Program Files`, `Windows` excluding `Windows\Temp`).

## Notes & Limitations

- Group evaluation is **heuristic** (focus on broad groups like `Everyone`, `Authenticated Users`, `BUILTIN\Users`).
- **Nested AD group** expansion is not performed.
- Wildcard path NTFS checks use a **parent-directory heuristic** (best effort).
- Remote share ACL reads depend on **CIM/WMI/SMB** availability, firewall, and permissions.
- Symlink/junction/hardlink abuse checks are **not yet implemented**.
- Event log correlation (AppLocker `800x/802x`) is **not yet implemented**.

## Security Considerations

- The script is **read-only**; it does not change policies or ACLs.
- `Get-AppLockerPolicy -Effective` and ACL enumeration may require **elevation**.
- Use appropriate credentials for remote share checks and follow your org’s access policies.


## Troubleshooting

### “Get-AppLockerPolicy is not recognized”
- AppLocker cmdlets might not be available on this OS/edition. Ensure AppLocker is installed/supported.

### “Access denied” when exporting policy
- Start PowerShell **as Administrator**.

### Share ACL read fails
- Ensure the file server allows **CIM/WMI/SMB** queries.
- Use `-Credential (Get-Credential)` with an account that has rights.
- The tool emits an **Info** finding when it can’t read a share ACL.
