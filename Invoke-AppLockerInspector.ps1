Function Invoke-AppLockerInspector {
<#
.SYNOPSIS
  Audits an AppLocker policy XML and reports weak/misconfigured settings, including actual ACL checks.

.DESCRIPTION
  - If -Path is omitted, collects the local **effective** AppLocker policy and saves it to a file before auditing.
  - Validates RuleCollection enforcement (Enabled/AuditOnly/NotConfigured).
  - Flags risky Allow rules for broad principals (Everyone/Users/Authenticated Users).
  - Detects user-writable & overly broad path patterns, wildcards, UNC paths.
  - Highlights overly broad publisher rules (any publisher/product/binary, no upper version).
  - Tests permissions for UNC paths (Share + NTFS) and local paths (NTFS) to see if broad principals can Write/Modify/Full.
  - Emits structured findings with Severity, Reason, Recommendation.

.PARAMETER Path
  Optional path to an AppLocker XML export. If omitted, the function will create one using:
  Get-AppLockerPolicy -Effective -Xml

.PARAMETER OutPolicyXml
  Where to save the generated **effective** policy XML when -Path is omitted.
  Defaults to: $env:TEMP\AppLockerPolicy-<COMPUTERNAME>-yyyyMMdd-HHmmss.xml

.PARAMETER TestSharePermissions
  If set, attempt remote share ACL queries for UNC paths referenced by rules.

.PARAMETER Credential
  Optional credential used for remote share ACL queries.

.PARAMETER AsJson
  Output findings as JSON.

.PARAMETER OutCsv
  Export findings to CSV.

.PARAMETER OutHtml
  Export findings to HTML report.

.NOTES
  - Share ACL queries require appropriate rights on the file server and open firewalls.
  - Group expansion is heuristic for broad groups; deep nested group evaluation is out of scope.
#>

[CmdletBinding()]
param(
  [Parameter(Position=0)]
  [string]$Path,

  [string]$OutPolicyXml,

  [switch]$TestSharePermissions,

  [System.Management.Automation.PSCredential]$Credential,

  [switch]$AsJson,

  [string]$OutCsv,

  [string]$OutHtml
)

# ----------------------------- Helpers ------------------------------------
function Get-Art($Version) {
"
    _                _               _               ___                           _             
   / \   _ __  _ __ | |    ___   ___| | _____ _ __  |_ _|_ __  ___ _ __   ___  ___| |_ ___  _ __ 
  / _ \ | '_ \| '_ \| |   / _ \ / __| |/ / _ \ '__|  | || '_ \/ __| '_ \ / _ \/ __| __/ _ \| '__|
 / ___ \| |_) | |_) | |__| (_) | (__|   <  __/ |     | || | | \__ \ |_) |  __/ (__| || (_) | |   
/_/   \_\ .__/| .__/|_____\___/ \___|_|\_\___|_|    |___|_| |_|___/ .__/ \___|\___|\__\___/|_|   
        |_|   |_|                                                 |_|                                   
		By: Spencer Alessi (@techspence)
		Version $Version
"
}

function Resolve-SidOrName {
  param(
    [string]$SidOrName
  )
  if (-not $SidOrName) { 
    return $SidOrName 
  }
  if ($SidOrName -match '^S-\d-\d+-.+') {
    try {
      return ([System.Security.Principal.SecurityIdentifier]$SidOrName).
        Translate([System.Security.Principal.NTAccount]).Value
    } catch { return $SidOrName }
  }
  return $SidOrName
}

function Test-BroadPrincipal {
  param(
    [string]$SidOrName
  )
  $sid = $SidOrName
  $name = Resolve-SidOrName $SidOrName
  
  # Everyone, Auth Users, Users
  $broadSids = @('S-1-1-0','S-1-5-11','S-1-5-32-545')
  if ($sid -and $broadSids -contains $sid) { 
      return $true 
  }
  if ($name -match '(?i)^(Everyone|Authenticated Users|BUILTIN\\Users|Domain Users|Interactive)$') { 
    return $true 
  }
  return $false
}

function Test-AdminPrincipal {
  param(
    [string]$SidOrName
  )
  $sid = $SidOrName
  $name = Resolve-SidOrName $SidOrName

  # BUILTIN\Administrators
  if ($sid -eq 'S-1-5-32-544') { 
    return $true 
  } 
  if ($name -match '(?i)^BUILTIN\\Administrators$') { 
    return $true 
  }
  return $false
}

function Test-UserWritableOrBroadPath {
  param(
    [string]$PathText
  )
  if (-not $PathText) { 
    return $null 
  }
  $checks = @(
    @{ Regex='(?i)^\*$|^\*\\|^[A-Z]:\\\*$|^%OSDRIVE%\\\*';
       Reason='Wildcard or drive root';              
       Severity='High'   
      },
    @{ Regex='(?i)^\\\\';
       Reason='UNC/network path allowed';           
       Severity='High'   
      },
    @{ Regex='(?i)\\Windows\\Temp(\\|$)|(^|\\)Temp(\\|$)';     
       Reason='Temp folders are user-writable';     
       Severity='High'   
      },
    @{ Regex='(?i)\\Users(\\|$)|%USERPROFILE%|%LOCALAPPDATA%|%APPDATA%|%HOMEPATH%|%TMP%|%TEMP%';
       Reason='User profile/AppData is writable';    
       Severity='High'   
      },
    @{ Regex='(?i)\\(Downloads|Desktop|Documents)(\\|$)';      
       Reason='Common user-writable folders';       
       Severity='High'   
      },
    @{ Regex='(?i)\\Public(\\|$)';                             
       Reason='Public folders are shared/writable'; 
       Severity='Medium' 
      },
    @{ Regex='(?i)\\ProgramData(\\|$)';                        
       Reason='ProgramData often has writable subs';
       Severity='Medium' 
      }
  )
  foreach ($c in $checks) { 
    if ($PathText -match $c.Regex) { 
      return @{ Match=$true; Reason=$c.Reason; Severity=$c.Severity } 
    } 
  }
  if ($PathText -match '(?i)\\Program Files( \(x86\))?(\\|$)' -or $PathText -match '(?i)\\Windows(\\|$)') { 
    return $null 
  }
  return $null
}

# Protected bases (except Windows\Temp)
function Test-ProtectedPath {
  param(
    [string]$ExpandedLocalPath
  )
  if (-not $ExpandedLocalPath) { 
    return $false 
  }
  if ($ExpandedLocalPath -match '(?i)^[A-Z]:\\Windows\\Temp(\\|$)') { 
    return $false 
  }
  return ($ExpandedLocalPath -match '(?i)^[A-Z]:\\Program Files( \(x86\))?\\') -or
         ($ExpandedLocalPath -match '(?i)^[A-Z]:\\Windows(\\|$|\\.+)')
}

function New-Finding {
  param(
    [string]$Severity,
    
    [hashtable]$Props)
  
  [pscustomobject]@{
    Severity        = $Severity
    Collection      = $Props.Collection
    RuleType        = $Props.RuleType
    Action          = $Props.Action
    Principal       = $Props.Principal
    RuleName        = $Props.RuleName
    ConditionType   = $Props.ConditionType
    Condition       = $Props.Condition
    Reason          = $Props.Reason
    Recommendation  = $Props.Recommendation
  }
}

# ----- Env/macros expansion for local paths -----

function Expand-PathMacros {
  param(
    [string]$PathText
  )
  if (-not $PathText) { 
    return $null 
  }
  # Expand %ENV% tokens using .NET
  $expanded = [Environment]::ExpandEnvironmentVariables($PathText)

  # %OSDRIVE% common macro
  if ($expanded -match '(?i)%OSDRIVE%') {
    $sysDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Root -match '^[A-Z]:\\$'} | Sort-Object Used -Descending | Select-Object -First 1).Root.TrimEnd('\')
    if (-not $sysDrive) { 
      $sysDrive = "$($env:SystemDrive)" 
    }
    $expanded = $expanded -replace '(?i)%OSDRIVE%',$sysDrive
  }

  # Normalize double backslashes in middle (not leading for UNC)
  $expanded = $expanded -replace '(?<!^|\\)\\{2,}','\'
  return $expanded
}

# ----- UNC share helpers -----

function Get-ShareRoot { 
  param(
    [string]$UncPath
  ) 
  if ($UncPath -notmatch '^(\\\\[^\\]+)\\([^\\]+)') { 
    return $null 
  } 
  
  "$($Matches[1])\$($Matches[2])" 
}
function Split-Share   { 
  param(
    [string]$UncPath
  ) 
  if ($UncPath -notmatch '^(\\\\[^\\]+)\\([^\\]+)') {
     return $null 
  } 
  
  [pscustomobject]@{ 
    Server=$Matches[1].TrimStart('\') 
    Share=$Matches[2] 
  } 
}

function New-CimOrWmi {
  param(
    [string]$ComputerName, 
    
    [System.Management.Automation.PSCredential]$Credential
  )
  try {
    $cim = New-CimSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
    return @{ 
      Type='CIM'
      Session=$cim 
    }
  } catch {
    try {
      $opt = New-Object System.Management.ConnectionOptions
      if ($Credential) { 
        $opt.Username = $Credential.UserName
        $opt.SecurePassword = $Credential.Password 
      }
      $scope = New-Object System.Management.ManagementScope("\\$ComputerName\root\cimv2",$opt)
      $scope.Connect()
      return @{ 
        Type='WMI'
        Scope=$scope 
      }
    } catch { 
      return $null 
    }
  }
}

function Get-ShareAclInfo {
  param(
    [string]$Server, 
    
    [string]$Share, 
    
    [System.Management.Automation.PSCredential]$Credential
  )
  $sess = New-CimOrWmi -ComputerName $Server -Credential $Credential
  if (-not $sess) { 
    return $null 
  }

  if ($sess.Type -eq 'CIM') {
    try {
      $acc = Get-SmbShareAccess -CimSession $sess.Session -Name $Share -ErrorAction Stop
      return ($acc | Select-Object @{n='Account';e={$_.AccountName}},
                               @{n='AccessRight';e={$_.AccessRight}},
                               @{n='AccessControlType';e={$_.AccessControlType}})
    } catch { 
      return $null 
    }
  } else {
    try {
      $q = New-Object System.Management.ObjectQuery("SELECT * FROM Win32_LogicalShareSecuritySetting WHERE Name='$Share'")
      $searcher = New-Object System.Management.ManagementObjectSearcher($sess.Scope,$q)
      $obj = $searcher.Get() | Select-Object -First 1
      if (-not $obj) { 
        return $null 
      }
      $sd = ([WMI]$obj.__PATH).GetSecurityDescriptor().Descriptor
      $mapCtrl = @{ 
        2032127='Full'
        1245631='Change'
        1179817='Read' 
      }
      $aces = @()
      foreach ($dacl in $sd.DACL) {
        $acct = try {
          $sid = New-Object System.Security.Principal.SecurityIdentifier($dacl.Trustee.SID)
          $sid.Translate([System.Security.Principal.NTAccount]).Value
        } catch { $dacl.Trustee.Name }
        $aces += [pscustomobject]@{
          Account           = $acct
          AccessRight       = $mapCtrl[[int]$dacl.AccessMask]
          AccessControlType = (if ($dacl.AceType -eq 0) {
            'Allow'
          } else {
            'Deny'
          })
        }
      }
      return $aces
    } catch { 
      return $null 
    }
  }
}

function Test-ShareWritableForPrincipal {
  param(
    [array]$ShareAclRows, 
    
    [string[]]$PrincipalNames
  )
  if (-not $ShareAclRows) { 
    return $false 
  }
  $writableTags = @('Change','Full','Modify','Write')
  foreach ($p in $PrincipalNames) {
    $hits = $ShareAclRows | Where-Object { $_.Account -ieq $p -or ($_.Account -match '(?i)\\Users$|^Everyone$|Authenticated Users') }
    if ($hits) {
      if ($hits | Where-Object { $_.AccessControlType -eq 'Deny' -and ($writableTags -contains $_.AccessRight) }) { 
        return $false 
      }
      if ($hits | Where-Object { $_.AccessControlType -eq 'Allow' -and ($writableTags -contains $_.AccessRight) }) { 
        return $true 
      }
    }
  }
  return $false
}


function Test-EffectiveNtfsRights {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string[]]$Principal
    )

    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        foreach ($p in $Principal) {
            $resolvedPrincipal = $p
            if ($resolvedPrincipal -match '^S-\d-\d+(-\d+)+$') {
                try {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($resolvedPrincipal)
                    $resolvedPrincipal = $sid.Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    continue
                }
            }

            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference -like "*$resolvedPrincipal") {
                    if ($ace.AccessControlType -eq 'Allow' -and
                        $ace.FileSystemRights -match 'Write|Modify|FullControl') {
                        return $true
                    }
                }
            }
        }
    } catch {
        Write-Verbose "Failed to check rights on $Path for $Principal`: $_"
    }
    return $false
}


function Resolve-BroadPrincipalNames {
  param([string[]]$UserOrGroupSid)
  $names = @()
  foreach ($sid in $UserOrGroupSid) {
    $n = $sid
    if ($sid -match '^S-\d-') { 
      try { 
        $n = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value 
      } catch {} 
    }
    $names += $n
  }
  $names += 'Everyone','Authenticated Users','BUILTIN\Users'
  $names | Select-Object -Unique
}

# ----- HTML Report Generation -----

# Load required assemblies for HTML encoding
Add-Type -AssemblyName System.Web

function Get-SecurityInsights {
  param([array]$Results)
  
  $insights = @{}
  
  # Check for dangerous wildcard rules
  $dangerousWildcards = $Results | Where-Object { 
    $_.ConditionType -eq 'Path' -and 
    $_.Condition -and 
    ($_.Condition -match '\*\.?\*' -or $_.Condition -match '^[A-Z]:\\?\*' -or $_.Condition -match '%PROGRAMFILES%\\?\*' -or $_.Condition -match '%WINDIR%\\?\*')
  }
  $insights['dangerousWildcards'] = $dangerousWildcards.Count
  
  # Check for UNC paths
  $uncPaths = $Results | Where-Object { 
    $_.ConditionType -eq 'Path' -and 
    $_.Condition -and 
    $_.Condition -match '^\\\\' 
  }
  $insights['uncPaths'] = $uncPaths.Count
  
  # Check for user-writable paths
  $userWritablePaths = $Results | Where-Object { 
    $_.Reason -and 
    ($_.Reason -match '(?i)(user.writable|appdata|temp|downloads|desktop|documents)' -or 
     $_.Reason -match '(?i)(broad principal|everyone)')
  }
  $insights['userWritablePaths'] = $userWritablePaths.Count
  
  # Check for broad principals
  $broadPrincipals = $Results | Where-Object { 
    $_.Principal -and 
    ($_.Principal -match '(?i)(everyone|authenticated users|users)' -or $_.Reason -match '(?i)broad.*principal')
  }
  $insights['broadPrincipals'] = $broadPrincipals.Count
  
  # Check for enforcement issues
  $enforcementIssues = $Results | Where-Object { 
    $_.Reason -and 
    ($_.Reason -match '(?i)(notconfigured|auditonly|default.allow)' -or $_.RuleType -eq '(collection)')
  }
  $insights['enforcementIssues'] = $enforcementIssues.Count
  
  return $insights
}

function New-HtmlReport {
  param(
    [array]$Results,
    [string]$OutputPath
  )
  
  Write-Verbose "New-HtmlReport called with $($Results.Count) results"
  Write-Verbose "Output path: $OutputPath"
  
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $totalFindings = $Results.Count
  $highSeverity = ($Results | Where-Object { $_.Severity -eq 'High' }).Count
  $mediumSeverity = ($Results | Where-Object { $_.Severity -eq 'Medium' }).Count
  $lowSeverity = ($Results | Where-Object { $_.Severity -eq 'Low' }).Count
  $infoSeverity = ($Results | Where-Object { $_.Severity -eq 'Info' }).Count
  
  $collections = ($Results | Select-Object -ExpandProperty Collection -Unique | Sort-Object) -join ', '
  $insights = Get-SecurityInsights -Results $Results
  
  $htmlHeader = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AppLocker Inspector Report</title>
    <style>
        :root {
            --bg-color: #ffffff;
            --text-color: #2c3e50;
            --header-bg: #34495e;
            --header-text: #ffffff;
            --table-border: #bdc3c7;
            --table-hover: #ecf0f1;
            --high-severity: #e74c3c;
            --medium-severity: #f39c12;
            --low-severity: #f1c40f;
            --info-severity: #3498db;
            --success-color: #27ae60;
            --card-bg: #f8f9fa;
            --shadow: rgba(0,0,0,0.1);
            --warning-color: #e67e22;
            --danger-bg: #fdf2f2;
            --warning-bg: #fef9e7;
            --info-bg: #f0f9ff;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            transition: all 0.3s ease;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, var(--header-bg), #2c3e50);
            color: var(--header-text);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 15px var(--shadow);
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grain" width="100" height="100" patternUnits="userSpaceOnUse"><circle cx="25" cy="25" r="1" fill="rgba(255,255,255,0.1)"/><circle cx="75" cy="75" r="1" fill="rgba(255,255,255,0.1)"/></pattern></defs><rect width="100" height="100" fill="url(%23grain)"/></svg>');
            opacity: 0.1;
        }
        
        .header-content {
            position: relative;
            z-index: 1;
        }
        
        .ascii-art {
            font-family: 'Courier New', monospace;
            font-size: 10px;
            white-space: pre;
            margin-bottom: 20px;
            opacity: 0.8;
        }
        
        .title {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 20px;
        }
        
        .security-insights {
            background: var(--danger-bg);
            border-left: 5px solid var(--high-severity);
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px var(--shadow);
        }
        
        .security-insights h2 {
            color: var(--high-severity);
            margin-bottom: 15px;
            font-size: 1.5em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .security-insights h2::before {
            content: "⚠️";
            font-size: 1.2em;
        }
        
        .insights-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .insight-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid var(--warning-color);
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .insight-card.critical {
            border-left-color: var(--high-severity);
        }
        
        .insight-card h3 {
            color: var(--text-color);
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .insight-card p {
            color: #666;
            line-height: 1.5;
            margin-bottom: 10px;
        }
        
        .insight-impact {
            background: var(--warning-bg);
            padding: 10px;
            border-radius: 4px;
            font-size: 0.9em;
            color: #8b5a2b;
            font-weight: 500;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--card-bg);
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 15px var(--shadow);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border-left: 5px solid transparent;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px var(--shadow);
        }
        
        .stat-card.high { border-left-color: var(--high-severity); }
        .stat-card.medium { border-left-color: var(--medium-severity); }
        .stat-card.low { border-left-color: var(--low-severity); }
        .stat-card.info { border-left-color: var(--info-severity); }
        .stat-card.total { border-left-color: var(--success-color); }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 1.1em;
            opacity: 0.8;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .filters {
            margin-bottom: 20px;
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
        }
        
        .filter-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .filter-group label {
            font-weight: 600;
            min-width: 80px;
        }
        
        select, input {
            padding: 8px 12px;
            border: 2px solid var(--table-border);
            border-radius: 6px;
            background: var(--bg-color);
            color: var(--text-color);
            font-size: 14px;
            transition: border-color 0.3s ease;
        }
        
        select:focus, input:focus {
            outline: none;
            border-color: var(--info-severity);
        }
        
        .table-container {
            background: var(--card-bg);
            border-radius: 12px;
            overflow: auto;
            box-shadow: 0 4px 15px var(--shadow);
            margin-bottom: 30px;
            max-width: 100%;
            /* Enable horizontal scrolling */
            overflow-x: auto;
            overflow-y: auto;
            max-height: 80vh;
        }
        
        table {
            width: 100%;
            min-width: 1800px; /* Much wider to accommodate content */
            border-collapse: collapse;
            font-size: 14px;
            table-layout: fixed; /* Fixed layout for better control */
        }
        
        th {
            background: var(--header-bg);
            color: var(--header-text);
            padding: 15px 12px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
            cursor: pointer;
            user-select: none;
            transition: background-color 0.3s ease;
            white-space: nowrap;
        }
        
        /* Column width optimization - much more generous */
        th:nth-child(1) { width: 90px; }    /* Severity */
        th:nth-child(2) { width: 120px; }   /* Collection */
        th:nth-child(3) { width: 120px; }   /* Rule Type */
        th:nth-child(4) { width: 80px; }    /* Action */
        th:nth-child(5) { width: 130px; }   /* Principal */
        th:nth-child(6) { width: 200px; }   /* Rule Name */
        th:nth-child(7) { width: 120px; }   /* Condition Type */
        th:nth-child(8) { width: 250px; }   /* Condition */
        th:nth-child(9) { width: 400px; }   /* Reason - Much wider */
        th:nth-child(10) { width: 400px; }  /* Recommendation - Much wider */
        
        th:hover {
            background: #2c3e50;
        }
        
        th.sort-asc::after { content: ' ↑'; }
        th.sort-desc::after { content: ' ↓'; }
        
        td {
            padding: 12px;
            border-bottom: 1px solid var(--table-border);
            vertical-align: top;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        
        /* Match column widths for td elements */
        td:nth-child(1) { width: 90px; }
        td:nth-child(2) { width: 120px; }
        td:nth-child(3) { width: 120px; }
        td:nth-child(4) { width: 80px; }
        td:nth-child(5) { width: 130px; }
        td:nth-child(6) { width: 200px; }
        td:nth-child(7) { width: 120px; }
        td:nth-child(8) { width: 250px; }
        td:nth-child(9) { width: 400px; }   /* Reason - Much wider */
        td:nth-child(10) { width: 400px; }  /* Recommendation - Much wider */
        
        tr:hover {
            background-color: var(--table-hover);
        }
        
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: white;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
        }
        
        .severity-high { background: var(--high-severity); }
        .severity-medium { background: var(--medium-severity); }
        .severity-low { background: var(--low-severity); }
        .severity-info { background: var(--info-severity); }
        
        .expandable {
            line-height: 1.4;
            word-wrap: break-word;
            hyphens: auto;
            cursor: pointer;
            position: relative;
        }
        
        /* Only truncate if content is REALLY long (more than 8 lines) */
        .expandable:not(.expanded) {
            max-height: 140px; /* Allow about 8-9 lines before truncating */
            overflow: hidden;
            position: relative;
        }
        
        /* Add fade effect for truncated content */
        .expandable:not(.expanded)::after {
            content: "";
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 20px;
            background: linear-gradient(transparent, var(--card-bg));
            pointer-events: none;
        }
        
        .expandable.expanded {
            max-height: none;
            word-wrap: break-word;
        }
        
        .expandable:hover {
            background-color: rgba(52, 152, 219, 0.05);
            border-radius: 4px;
        }
        
        /* Visual indicator for expandable content */
        .expandable:not(.expanded):hover::before {
            content: "Click to expand...";
            position: absolute;
            bottom: 2px;
            right: 4px;
            background: var(--info-severity);
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
            z-index: 5;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: var(--text-color);
            opacity: 0.7;
            border-top: 1px solid var(--table-border);
            margin-top: 40px;
        }
        
        /* Scroll indicator */
        .table-container::after {
            content: "← Scroll horizontally to see all columns →";
            position: sticky;
            left: 0;
            bottom: 0;
            background: var(--header-bg);
            color: var(--header-text);
            padding: 8px;
            text-align: center;
            font-size: 12px;
            opacity: 0.8;
            border-top: 1px solid var(--table-border);
        }
        
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .title { font-size: 2em; }
            .stats-grid { grid-template-columns: 1fr; }
            .insights-grid { grid-template-columns: 1fr; }
            .insight-card { margin-bottom: 15px; }
            .filters { flex-direction: column; align-items: stretch; }
            
            table { 
                font-size: 12px;
                min-width: 1400px; /* Wider minimum for mobile horizontal scroll */
            }
            
            th, td { 
                padding: 6px 8px;
                font-size: 11px;
            }
            
            /* Adjust column widths for mobile - still generous */
            th:nth-child(1), td:nth-child(1) { width: 70px; }
            th:nth-child(2), td:nth-child(2) { width: 100px; }
            th:nth-child(3), td:nth-child(3) { width: 100px; }
            th:nth-child(4), td:nth-child(4) { width: 70px; }
            th:nth-child(5), td:nth-child(5) { width: 110px; }
            th:nth-child(6), td:nth-child(6) { width: 150px; }
            th:nth-child(7), td:nth-child(7) { width: 100px; }
            th:nth-child(8), td:nth-child(8) { width: 200px; }
            th:nth-child(9), td:nth-child(9) { width: 300px; }
            th:nth-child(10), td:nth-child(10) { width: 300px; }
        }
        
        /* Large screen optimization */
        @media (min-width: 1600px) {
            .table-container {
                max-height: 85vh;
            }
            
            table {
                min-width: 2000px; /* Even wider for large screens */
            }
            
            /* Give even more space to important columns on large screens */
            th:nth-child(8), td:nth-child(8) { width: 300px; }    /* Condition */
            th:nth-child(9), td:nth-child(9) { width: 450px; }    /* Reason */
            th:nth-child(10), td:nth-child(10) { width: 450px; }  /* Recommendation */
        }
        
        /* Ultra-wide screen optimization */
        @media (min-width: 2000px) {
            table {
                min-width: 2400px;
            }
            
            th:nth-child(9), td:nth-child(9) { width: 500px; }
            th:nth-child(10), td:nth-child(10) { width: 500px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div class="ascii-art">    _                _               _               ___                           _             
   / \   _ __  _ __ | |    ___   ___| | _____ _ __  |_ _|_ __  ___ _ __   ___  ___| |_ ___  _ __ 
  / _ \ | '_ \| '_ \| |   / _ \ / __| |/ / _ \ '__|  | || '_ \/ __| '_ \ / _ \/ __| __/ _ \| '__|
 / ___ \| |_) | |_) | |__| (_) | (__|   <  __/ |     | || | | \__ \ |_) |  __/ (__| || (_) | |   
/_/   \_\ .__/| .__/|_____\___/ \___|_|\_\___|_|    |___|_| |_|___/ .__/ \___|\___|\__\___/|_|   
        |_|   |_|                                                 |_|                         </div>
                <h1 class="title">AppLocker Inspector Report</h1>
                <p class="subtitle">Security Policy Analysis & Recommendations</p>
                <p>Generated on: $timestamp</p>
                <p>Collections Analyzed: $collections</p>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card total">
                <div class="stat-number">$totalFindings</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">$highSeverity</div>
                <div class="stat-label">High Severity</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">$mediumSeverity</div>
                <div class="stat-label">Medium Severity</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">$lowSeverity</div>
                <div class="stat-label">Low Severity</div>
            </div>
            <div class="stat-card info">
                <div class="stat-number">$infoSeverity</div>
                <div class="stat-label">Info</div>
            </div>
        </div>
        
        <div class="security-insights">
            <h2>🚨 Critical Security Insights</h2>
            <p>Based on our analysis of your AppLocker policy, here are the most important security considerations:</p>
            
            <div class="insights-grid">
                <div class="insight-card critical">
                    <h3>🏛️ User-Mode Enforcement Limitations</h3>
                    <p>AppLocker operates in user-mode, which makes it more vulnerable to bypass techniques compared to kernel-level solutions like Windows Defender Application Control (WDAC). Consider WDAC for enhanced security requirements.</p>
                    <div class="insight-impact">
                        <strong>Impact:</strong> User-mode enforcement can be bypassed through various techniques including DLL injection, process hollowing, and PowerShell execution policy bypasses. WDAC provides kernel-level protection that's significantly harder to circumvent.
                    </div>
                </div>
                
                <div class="insight-card critical">
                    <h3>⚡ Dangerous Wildcard Rules ($($insights['dangerousWildcards']) found)</h3>
                    <p>Rules using patterns like *, *.*, %PROGRAMFILES%\\*, or C:\\* are extremely dangerous as they effectively disable application control for large parts of the filesystem.</p>
                    <div class="insight-impact">
                        <strong>Impact:</strong> These patterns create massive security gaps that attackers can easily exploit by placing malicious files in allowed locations.
                    </div>
                </div>
                
                <div class="insight-card critical">
                    <h3>🌐 Network Path Vulnerabilities ($($insights['uncPaths']) found)</h3>
                    <p>Rules allowing execution from UNC/network paths (\\\\server\\share) create security risks as network shares may be compromised or hijacked by attackers.</p>
                    <div class="insight-impact">
                        <strong>Impact:</strong> Attackers can compromise network shares or perform SMB relay attacks to execute malicious code through these rules.
                    </div>
                </div>
                
                <div class="insight-card">
                    <h3>📂 User-Writable Directory Rules ($($insights['userWritablePaths']) found)</h3>
                    <p>Rules allowing execution from user-writable directories (AppData, Temp, Downloads, etc.) are primary targets for malware persistence and are used in 70% of successful endpoint compromises.</p>
                    <div class="insight-impact">
                        <strong>Impact:</strong> Malware commonly uses these locations for persistence and lateral movement within your environment.
                    </div>
                </div>
                
                <div class="insight-card">
                    <h3>🔐 Broad Principal Assignments ($($insights['broadPrincipals']) found)</h3>
                    <p>Rules assigned to "Everyone", "Authenticated Users", or "Users" groups may be overly broad and could impact system security and administrative functions.</p>
                    <div class="insight-impact">
                        <strong>Impact:</strong> Overly broad assignments can prevent legitimate administrative tasks and make it harder to implement principle of least privilege.
                    </div>
                </div>
                
                <div class="insight-card">
                    <h3>🚀 Consider WDAC for Enhanced Security</h3>
                    <p>For organizations requiring maximum security, Windows Defender Application Control (WDAC) offers kernel-level enforcement, better performance, and modern application support that complements or can replace AppLocker.</p>
                    <div class="insight-impact">
                        <strong>Benefit:</strong> WDAC provides kernel-level protection, better performance with intelligent caching, support for modern app types (MSIX/UWP), and integration with Microsoft security stack.
                    </div>
                </div>
            </div>
        </div>
        
        <div class="filters">
            <div class="filter-group">
                <label>Severity:</label>
                <select id="severityFilter" onchange="filterTable()">
                    <option value="">All</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Info">Info</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Collection:</label>
                <select id="collectionFilter" onchange="filterTable()">
                    <option value="">All</option>
"@

  $uniqueCollections = $Results | Select-Object -ExpandProperty Collection -Unique | Sort-Object
  foreach ($collection in $uniqueCollections) {
    $htmlHeader += "                    <option value=`"$collection`">$collection</option>`n"
  }

  $htmlHeader += @"
                </select>
            </div>
            <div class="filter-group">
                <label>Search:</label>
                <input type="text" id="searchInput" placeholder="Search in findings..." onkeyup="filterTable()">
            </div>
        </div>
        
        <div class="table-container">
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">Severity</th>
                        <th onclick="sortTable(1)">Collection</th>
                        <th onclick="sortTable(2)">Rule Type</th>
                        <th onclick="sortTable(3)">Action</th>
                        <th onclick="sortTable(4)">Principal</th>
                        <th onclick="sortTable(5)">Rule Name</th>
                        <th onclick="sortTable(6)">Condition Type</th>
                        <th onclick="sortTable(7)">Condition</th>
                        <th onclick="sortTable(8)">Reason</th>
                        <th onclick="sortTable(9)">Recommendation</th>
                    </tr>
                </thead>
                <tbody>
"@

  $htmlRows = ""
  foreach ($result in $Results) {
    $severityClass = "severity-$($result.Severity.ToLower())"
    $htmlRows += @"
                    <tr>
                        <td><span class="severity-badge $severityClass">$($result.Severity)</span></td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($result.Collection))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($result.RuleType))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($result.Action))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($result.Principal))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($result.RuleName))</td>
                        <td>$([System.Web.HttpUtility]::HtmlEncode($result.ConditionType))</td>
                        <td class="expandable" onclick="toggleExpand(this)">$([System.Web.HttpUtility]::HtmlEncode($result.Condition))</td>
                        <td class="expandable" onclick="toggleExpand(this)">$([System.Web.HttpUtility]::HtmlEncode($result.Reason))</td>
                        <td class="expandable" onclick="toggleExpand(this)">$([System.Web.HttpUtility]::HtmlEncode($result.Recommendation))</td>
                    </tr>
"@
  }

  $htmlFooter = @"
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>AppLocker Inspector v0.1 | Generated by ApplockerInspector</p>
            <p>For more information and updates, visit the <a href="https://github.com/techspence/applockerinspector" target="_blank" rel="noopener noreferrer">project repository</a></p>
        </div>
    </div>

    <script>
        let sortDirection = {};
        
        function sortTable(columnIndex) {
            const table = document.getElementById('findingsTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const th = table.querySelectorAll('th')[columnIndex];
            
            // Clear other sort indicators
            table.querySelectorAll('th').forEach(header => {
                header.classList.remove('sort-asc', 'sort-desc');
            });
            
            const isAscending = !sortDirection[columnIndex];
            sortDirection[columnIndex] = isAscending;
            
            rows.sort((a, b) => {
                const cellA = a.cells[columnIndex].textContent.trim();
                const cellB = b.cells[columnIndex].textContent.trim();
                
                // Special handling for severity
                if (columnIndex === 0) {
                    const severityOrder = { 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1 };
                    const valueA = severityOrder[cellA.toUpperCase()] || 0;
                    const valueB = severityOrder[cellB.toUpperCase()] || 0;
                    return isAscending ? valueA - valueB : valueB - valueA;
                }
                
                return isAscending ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
            });
            
            rows.forEach(row => tbody.appendChild(row));
            th.classList.add(isAscending ? 'sort-asc' : 'sort-desc');
        }
        
        function filterTable() {
            const severityFilter = document.getElementById('severityFilter').value.toLowerCase();
            const collectionFilter = document.getElementById('collectionFilter').value.toLowerCase();
            const searchInput = document.getElementById('searchInput').value.toLowerCase();
            const table = document.getElementById('findingsTable');
            const rows = table.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                const severity = row.cells[0].textContent.toLowerCase();
                const collection = row.cells[1].textContent.toLowerCase();
                const rowText = row.textContent.toLowerCase();
                
                const severityMatch = !severityFilter || severity.includes(severityFilter);
                const collectionMatch = !collectionFilter || collection.includes(collectionFilter);
                const searchMatch = !searchInput || rowText.includes(searchInput);
                
                row.style.display = severityMatch && collectionMatch && searchMatch ? '' : 'none';
            });
        }
        
        function toggleExpand(element) {
            element.classList.toggle('expanded');
        }
        
        // Initialize table with default sort by severity
        document.addEventListener('DOMContentLoaded', function() {
            sortTable(0);
        });
    </script>
</body>
</html>
"@

  Write-Verbose "Building final HTML content..."
  $htmlContent = $htmlHeader + $htmlRows + $htmlFooter
  Write-Verbose "HTML content length: $($htmlContent.Length) characters"
  
  try {
    Write-Verbose "Writing HTML file to: $OutputPath"
    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Verbose "HTML report generated at: $OutputPath"
    
    # Verify the file was written
    if (Test-Path -LiteralPath $OutputPath) {
      Write-Verbose "File verification successful"
      return $true
    } else {
      Write-Warning "File was not created despite no errors"
      return $false
    }
  } catch {
    Write-Warning "Failed to generate HTML report: $($_.Exception.Message)"
    Write-Verbose "Full error details: $($_.Exception.ToString())"
    return $false
  }
}

# ----------------------------- Acquire / Parse XML ----------------------------------

Get-Art 0.1

$xml = $null

$SeverityScore = @{ High=3; Medium=2; Low=1; Info=0 }

if ([string]::IsNullOrWhiteSpace($Path)) {
  try {
    Write-Verbose "No -Path supplied. Collecting effective AppLocker policy..."
    $xmlText = Get-AppLockerPolicy -Effective -Xml
    if (-not $xmlText) { 
      throw "Get-AppLockerPolicy returned no XML." 
    }

    if (-not $OutPolicyXml -or [string]::IsNullOrWhiteSpace($OutPolicyXml)) {
      $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
      $OutPolicyXml = Join-Path $env:TEMP ("AppLockerPolicy-$env:COMPUTERNAME-$stamp.xml")
    }
    # Ensure directory exists
    $dir = Split-Path -Parent $OutPolicyXml
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { 
      New-Item -ItemType Directory -Force -Path $dir | Out-Null 
    }

    $xmlText | Out-File -LiteralPath $OutPolicyXml -Encoding UTF8
    Write-Verbose "Saved effective policy to '$OutPolicyXml'."

    [xml]$xml = $xmlText  }
  catch {
    throw "Failed to retrieve effective AppLocker policy: $($_.Exception.Message)"
  }
}
else {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "AppLocker policy file not found: $Path"
  }
  [xml]$xml = Get-Content -Raw -LiteralPath $Path
}

if (-not $xml.AppLockerPolicy) { 
  throw "This does not look like an AppLocker policy XML." 
}

$results = New-Object System.Collections.Generic.List[object]
$collections = @($xml.AppLockerPolicy.RuleCollection)
if (-not $collections -or $collections.Count -eq 0) { $collections = @($xml.SelectNodes('//RuleCollection')) }

# ----------------------------- Audit --------------------------------------

foreach ($col in $collections) {
  $colType = $col.Type
  if (-not $colType) { 
    if ($col.FilePathRule -or $col.FilePublisherRule -or $col.FileHashRule) { 
      $colType = '(Unknown)' 
    } 
  }

  $enf = $col.EnforcementMode; if (-not $enf) { 
    $enf = 'NotConfigured' 
  }
  switch -Regex ($enf) {
    'NotConfigured' {
      $results.Add( (New-Finding -Severity 'High' -Props @{
        Collection = $colType
        RuleType='(collection)'
        Reason="Collection '$colType' is NotConfigured → default-allow for this type."
        Recommendation = "Set EnforcementMode='Enabled' for '$colType' (or 'AuditOnly' during pilot)."
      }) )
    }
    '^AuditOnly$' {
      $results.Add( (New-Finding -Severity 'High' -Props @{
        Collection = $colType
        RuleType='(collection)'
        Reason="Collection '$colType' is AuditOnly (no blocking)."
        Recommendation = "Switch '$colType' to 'Enabled'. Note: Script collection in AuditOnly will not enforce Constrained Language Mode."
      }) )
    }
  }

  $allRules = @()
  if ($col.FilePathRule) { 
    $allRules += @($col.FilePathRule) 
  }
  if ($col.FilePublisherRule) { 
    $allRules += @($col.FilePublisherRule)
  }
  if ($col.FileHashRule) { 
    $allRules += @($col.FileHashRule) 
  }

  foreach ($r in $allRules) {
    $ruleType = $r.NodeName
    $action = [string]$r.Action
    $principal = [string]$r.UserOrGroupSid
    $principalN = Resolve-SidOrName $principal
    $isBroad = Test-BroadPrincipal $principal
    $isAdmin = Test-AdminPrincipal $principal

    $condType = ''; $condText = ''
    $reasons = @(); $rec = @(); $score = -1
    $exceptionCount = 0
    if ($r.Exceptions) {
      $exceptionCount = 0 + @($r.Exceptions.FilePathCondition).Count + @($r.Exceptions.FilePublisherCondition).Count + @($r.Exceptions.FileHashCondition).Count
    }

    # Track local NTFS rights for severity downgrades
    $localNtfsRight = $null
    $expanded = $null
    $isLocalPath = $false
    $hasWildcard = $false

    if ($r.Conditions.FilePathCondition) {
      $condType = 'Path'
      $condText = [string]$r.Conditions.FilePathCondition.Path

      if ($action -match 'Allow') {
        $hit = Test-UserWritableOrBroadPath $condText
        if ($hit) {
          $sev = $hit.Severity
          if ($isBroad -and -not $isAdmin -and $sev -eq 'Medium') { $sev = 'High' }
          $reasons += $hit.Reason
          $rec += "Replace broad path Allow with Publisher or Hash rules limited to required binaries."
          $rec += "Avoid allowing user-writable paths for non-admin principals."
          $score = [Math]::Max($score, $SeverityScore[$sev])
        }
        if ($condText -match '(?i)\*\.[a-z0-9]{2,4}|\*\.\*') {
          $reasons += "Wildcard extension pattern ($($Matches[0]))"
          $rec     += "Constrain by exact file or trusted publisher; avoid wildcard extensions."
          $score = [Math]::Max($score, $SeverityScore['Medium'])
        }
        if ($condText -match '(?i)^[A-Z]:\\$|^%OSDRIVE%\\\*$') {
          $reasons += "Root of OS drive allowed"
          $rec     += "Never allow entire drives; scope to trusted directories only."
          $score = [Math]::Max($score, $SeverityScore['High'])
        }
        if ($isBroad -and -not $isAdmin) {
          $reasons += "Principal is broad (Everyone/Authenticated Users/Users)"
          $rec     += "Restrict the principal to a minimal, purpose-built group."
          $score = [Math]::Max($score, $SeverityScore['Medium'])
        }
        # Check for any wildcard in path (covers *, ?, and other patterns)
        if ($condText -match '[\*\?]' -and -not ($reasons | Where-Object { $_ -match 'Wildcard' })) {
          $reasons += "Path contains wildcards allowing broader execution than intended"
          $rec     += "Use specific file paths or Publisher rules instead of wildcards."
          $score = [Math]::Max($score, $SeverityScore['Medium'])
        }
        if ($exceptionCount -gt 0 -and $score -gt 0) { $score -= 1 }
      }

      # ----- Local NTFS evaluation -----
      $expanded   = Expand-PathMacros $condText
      $isLocalPath = $expanded -match '^[A-Za-z]:\\'
      $hasWildcard = $expanded -match '[\*\?]'
      if ($isLocalPath -and -not $hasWildcard) {
        $broadNames = Resolve-BroadPrincipalNames @($principal)
        if (Test-Path -LiteralPath $expanded) {
          $localNtfsRight = Test-EffectiveNtfsRights -Path $expanded -Principal $broadNames
          if ($localNtfsRight -in @('Write','Modify','Full')) {
            $results.Add( (New-Finding -Severity 'High' -Props @{
              Collection=$colType
              RuleType=$ruleType
              Action=$action
              Principal=$principalN
              RuleName=[string]$r.Name
              ConditionType='Path'
              Condition=$condText
              Reason="Local NTFS grants $localNtfsRight to broad principals on $expanded"
              Recommendation="Harden NTFS ACL; remove write/modify for broad groups and restrict to specific app/service groups."
            }) )
          }
        } else {
          $results.Add( (New-Finding -Severity 'Info' -Props @{
            Collection=$colType
            RuleType=$ruleType
            Action=$action
            Principal=$principalN
            RuleName=[string]$r.Name
            ConditionType='Path'
            Condition=$condText
            Reason="Local path '$expanded' does not exist on this system (skipped NTFS check)"
            Recommendation="Validate on target systems where the path exists."
          }) )
        }
      } elseif ($isLocalPath -and $hasWildcard) {
        # Try parent directory if obvious (heuristic)
        $parent = Split-Path -Path $expanded -Parent -ErrorAction SilentlyContinue
        if ($parent -and (Test-Path -LiteralPath $parent)) {
          $broadNames = Resolve-BroadPrincipalNames @($principal)
          $ntfsParent = Test-EffectiveNtfsRights -Path $parent -Principal $broadNames
          if ($ntfsParent -in @('Write','Modify','Full')) {
            $results.Add( (New-Finding -Severity 'Medium' -Props @{
              Collection=$colType
              RuleType=$ruleType
              Action=$action
              Principal=$principalN
              RuleName=[string]$r.Name
              ConditionType='Path'
              Condition=$condText
              Reason="Wildcard path; parent '$parent' NTFS grants $ntfsParent to broad principals"
              Recommendation="Review NTFS ACL on parent and avoid wildcard allows on user-writable trees."
            }) )
          }
        }
      }

      # ----- UNC Share/NTFS evaluation -----
      if ($TestSharePermissions -and $condText -match '^(\\\\)') {
        $split = Split-Share -UncPath $condText
        if ($split) {
          $serverName = $split.Server
          $shareName = $split.Share
          $broadNames = Resolve-BroadPrincipalNames @($principal)
          $shareAcl = Get-ShareAclInfo -Server $serverName -Share $shareName -Credential $Credential
          $shareWritable = $false
          if ($shareAcl) {
            $shareWritable = Test-ShareWritableForPrincipal -ShareAclRows $shareAcl -PrincipalNames $broadNames
          } else {
            $results.Add( (New-Finding -Severity 'Info' -Props @{
              Collection=$colType
              RuleType=$ruleType
              Action=$action
              Principal=$principalN
              RuleName=[string]$r.Name
              ConditionType='Path'
              Condition=$condText
              Reason="Could not read share ACL on \\$serverName\$shareName (insufficient rights or remote management disabled)"
              Recommendation="Run with credentials that can query share permissions or audit directly on the file server."
            }) )
          }

          if ($shareWritable) {
            $results.Add( (New-Finding -Severity 'High' -Props @{
              Collection=$colType
              RuleType=$ruleType
              Action=$action
              Principal=$principalN
              RuleName=[string]$r.Name
              ConditionType='Path'
              Condition=$condText
              Reason="Share ACL on \\$serverName\$shareName grants Change/Full to broad principals"
              Recommendation="Tighten SMB share permissions: remove Change/Full for Everyone/Auth Users/Users."
            }) )
          }

          # NTFS on the UNC path itself (skip wildcards)
          if ($condText -notmatch '[\*\?]') {
            $ntfsRight = Test-EffectiveNtfsRights -Path $condText -Principal $broadNames
            if ($ntfsRight -in @('Write','Modify','Full')) {
              $results.Add( (New-Finding -Severity 'High' -Props @{
                Collection=$colType
                RuleType=$ruleType
                Action=$action
                Principal=$principalN
                RuleName=[string]$r.Name
                ConditionType='Path'
                Condition=$condText
                Reason="NTFS grants $ntfsRight to broad principals at UNC path"
                Recommendation="Harden NTFS ACL; remove write for broad groups and restrict to least-privilege groups."
              }) )
            }
          }
        }
      }

    } elseif ($r.Conditions.FilePublisherCondition) {
      $condType = 'Publisher'
      $c = $r.Conditions.FilePublisherCondition
      $publisher = [string]$c.PublisherName
      $product = [string]$c.ProductName
      $binary = [string]$c.BinaryName
      $range = $c.BinaryVersionRange
      $low = if ($range) { $range.LowSection; if (-not $low) { $low = $range.Low } }
      $high = if ($range) { $range.HighSection; if (-not $high){ $high= $range.High } }
      $condText = "Publisher='$publisher'; Product='$product'; Binary='$binary'; VersionRange=[$low,$high]"

      if ($action -match 'Allow') {
        if (-not $publisher -or $publisher -eq '*') {
          $reasons += "Any publisher allowed"
          $rec     += "Specify the exact trusted publisher (e.g., O=Vendor, C=...)."
          $score = [Math]::Max($score, $SeverityScore['High'])
        }
        if ($product -eq '*' -and $binary -eq '*') {
          $reasons += "Any product and any binary from the publisher are allowed"
          $rec     += "Constrain to specific Product and/or Binary where feasible."
          $score = [Math]::Max($score, $SeverityScore['Medium'])
        }
        if (-not $high -or $high -eq '*') {
          $reasons += "No upper version bound"
          $rec     += "Specify an upper version bound or update allow rules as versions are vetted."
          $score = [Math]::Max($score, $SeverityScore['Medium'])
        }
        if (Test-BroadPrincipal $principal -and -not (Test-AdminPrincipal $principal)) {
          $reasons += "Principal is broad (Everyone/Authenticated Users/Users)"
          $rec     += "Restrict the principal to a minimal, purpose-built group."
          $score = [Math]::Max($score, $SeverityScore['Medium'])
        }
        if ($exceptionCount -gt 0 -and $score -gt 0) { 
          $score -= 1 
        }
      }

      if ($score -ge 0 -and $reasons.Count -gt 0) {
        $sev = ($SeverityScore.GetEnumerator() | Sort-Object Value -Descending | Where-Object { $_.Value -le $score } | Select-Object -First 1).Key
        if (-not $sev) { 
          $sev = 'Info' 
        }
        $results.Add( (New-Finding -Severity $sev -Props @{
          Collection=$colType
          RuleType=$ruleType
          Action=$action
          Principal=$principalN
          RuleName=[string]$r.Name
          ConditionType=$condType
          Condition=$condText
          Reason=($reasons -join '; ')
          Recommendation= (($rec | Select-Object -Unique) -join ' ')
        }) )
      }

    } elseif ($r.Conditions.FileHashCondition) {
      $condType = 'Hash'
      $hashObjs = @($r.Conditions.FileHashCondition.FileHash)
      $hashList = if ($hashObjs) { ($hashObjs | ForEach-Object { $_.InputFileName }) -join '; ' } else { '<no-hash-names>' }
      $condText = "Hashes: $hashList"
      if ($action -match 'Allow' -and (Test-BroadPrincipal $principal) -and -not (Test-AdminPrincipal $principal)) {
        $results.Add( (New-Finding -Severity 'Low' -Props @{
          Collection=$colType
          RuleType=$ruleType
          Action=$action
          Principal=$principalN
          RuleName=[string]$r.Name
          ConditionType=$condType
          Condition=$condText
          Reason="Allow-by-hash is tight, but principal is overly broad"
          Recommendation="Assign allow-by-hash to a narrower group where feasible."
        }) )
      }
    }

    # ---- Emit path-based heuristic findings (with downgrade for protected, read-only local files) ----
    if ($condType -eq 'Path' -and $score -ge 0 -and $reasons.Count -gt 0) {
      $downgraded = $false
      if ($action -match 'Allow' -and $isBroad -and -not $isAdmin -and
          $isLocalPath -and -not $hasWildcard -and $expanded -and
          ($localNtfsRight -in @($null,'None','Read')) -and
          (Test-ProtectedPath -ExpandedLocalPath $expanded)) {
        $ntfsText = if ($null -eq $localNtfsRight) { 'Unknown' } else { $localNtfsRight }
        $reasons = @("Broad principal allowed, but target is in a protected location and not writable by broad principals (NTFS: $ntfsText)")
        $rec = @("No change needed if the file remains locked down; consider Publisher/Hash rules if you want defense-in-depth.")
        $sev = 'Info'
        $results.Add( (New-Finding -Severity $sev -Props @{
          Collection=$colType
          RuleType=$ruleType
          Action=$action
          Principal=$principalN
          RuleName=[string]$r.Name
          ConditionType=$condType
          Condition=$condText
          Reason=($reasons -join '; ')
          Recommendation=(($rec | Select-Object -Unique) -join ' ')
        }) )
        $downgraded = $true
      }

      if (-not $downgraded) {
        $sev = ($SeverityScore.GetEnumerator() | Sort-Object Value -Descending | Where-Object { $_.Value -le $score } | Select-Object -First 1).Key
        if (-not $sev) { 
          $sev = 'Info' 
        }
        $results.Add( (New-Finding -Severity $sev -Props @{
          Collection=$colType
          RuleType=$ruleType
          Action=$action
          Principal=$principalN
          RuleName=[string]$r.Name
          ConditionType=$condType
          Condition=$condText
          Reason=($reasons -join '; ')
          Recommendation=(($rec | Select-Object -Unique) -join ' ')
        }) )
      }
    }
    
    # ---- Ensure ALL findings with issues are emitted, even if they don't meet above criteria ----
    elseif ($condType -eq 'Path' -and $reasons.Count -gt 0) {
      # This catches cases where we found issues but didn't meet the specific criteria above
      $sev = if ($score -ge 0) {
        ($SeverityScore.GetEnumerator() | Sort-Object Value -Descending | Where-Object { $_.Value -le $score } | Select-Object -First 1).Key
      } else {
        'Medium'  # Default severity for path issues
      }
      if (-not $sev) { 
        $sev = 'Medium' 
      }
      
      $results.Add( (New-Finding -Severity $sev -Props @{
        Collection=$colType
        RuleType=$ruleType
        Action=$action
        Principal=$principalN
        RuleName=[string]$r.Name
        ConditionType=$condType
        Condition=$condText
        Reason=($reasons -join '; ')
        Recommendation=(($rec | Select-Object -Unique) -join ' ')
      }) )
    }

  }
}

# ----------------------------- Output -------------------------------------

$severityOrder = @{
    'High'   = 1
    'Medium' = 2
    'Low'    = 3
    'Info'   = 4
}

if ($OutCsv) {
  try {
    $results | Sort-Object { $severityOrder[$_.Severity] },Collection | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
    Write-Verbose "Wrote CSV to $OutCsv"
  } catch {
    Write-Warning "Failed writing CSV: $($_.Exception.Message)"
  }
}

if ($OutHtml) {
  Write-Host "Generating HTML report..." -ForegroundColor Yellow
  Write-Verbose "Total findings to include: $($results.Count)"
  Write-Verbose "Output path: $OutHtml"
  
  try {
    # Ensure the output directory exists
    $outputDir = Split-Path -Parent $OutHtml -ErrorAction SilentlyContinue
    if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
      Write-Verbose "Creating output directory: $outputDir"
      New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    }
    
    $sortedResults = $results | Sort-Object { $severityOrder[$_.Severity] },Collection
    Write-Verbose "Calling New-HtmlReport function..."
    $success = New-HtmlReport -Results $sortedResults -OutputPath $OutHtml
    
    if ($success) {
      Write-Host "HTML report generated successfully: $OutHtml" -ForegroundColor Green
      
      # Verify the file was actually created
      if (Test-Path -LiteralPath $OutHtml) {
        $fileSize = (Get-Item -LiteralPath $OutHtml).Length
        Write-Host "File size: $fileSize bytes" -ForegroundColor Cyan
        
        # Optionally open the HTML file
        if ($PSVersionTable.Platform -ne 'Unix') {
          try {
            Start-Process $OutHtml
          } catch {
            Write-Verbose "Could not auto-open HTML file: $($_.Exception.Message)"
          }
        }
      } else {
        Write-Warning "HTML file was not created at expected location: $OutHtml"
      }
    } else {
      Write-Warning "HTML report generation failed (function returned false)"
    }
  } catch {
    Write-Warning "Failed generating HTML report: $($_.Exception.Message)"
    Write-Warning "Full error: $($_.Exception.ToString())"
  }
}

if ($AsJson) {
  $results | ConvertTo-Json -Depth 6
} else {
  $results | Sort-Object { $severityOrder[$_.Severity] }, Collection, RuleType, RuleName
}

}