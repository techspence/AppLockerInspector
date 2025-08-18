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
  [string]$OutCsv
)

# ----------------------------- Helpers ------------------------------------

function Resolve-SidOrName {
  param([string]$SidOrName)
  if (-not $SidOrName) { return $SidOrName }
  if ($SidOrName -match '^S-\d-\d+-.+') {
    try {
      return ([System.Security.Principal.SecurityIdentifier]$SidOrName).
        Translate([System.Security.Principal.NTAccount]).Value
    } catch { return $SidOrName }
  }
  return $SidOrName
}

function Is-BroadPrincipal {
  param([string]$SidOrName)
  $sid = $SidOrName
  $name = Resolve-SidOrName $SidOrName
  $broadSids = @('S-1-1-0','S-1-5-11','S-1-5-32-545') # Everyone, Auth Users, Users
  if ($sid -and $broadSids -contains $sid) { return $true }
  if ($name -match '(?i)^(Everyone|Authenticated Users|BUILTIN\\Users|Domain Users|Interactive)$') { return $true }
  return $false
}

function Is-AdminPrincipal {
  param([string]$SidOrName)
  $sid = $SidOrName
  $name = Resolve-SidOrName $SidOrName
  if ($sid -eq 'S-1-5-32-544') { return $true } # BUILTIN\Administrators
  if ($name -match '(?i)^BUILTIN\\Administrators$') { return $true }
  return $false
}

function Test-UserWritableOrBroadPath {
  param([string]$PathText)
  if (-not $PathText) { return $null }
  $checks = @(
    @{ Re='(?i)^\*$|^\*\\|^[A-Z]:\\\*$|^%OSDRIVE%\\\*';      Reason='Wildcard or drive root';              Severity='High'   },
    @{ Re='(?i)^\\\\';                                      Reason='UNC/network path allowed';           Severity='High'   },
    @{ Re='(?i)\\Windows\\Temp(\\|$)|(^|\\)Temp(\\|$)';     Reason='Temp folders are user-writable';     Severity='High'   },
    @{ Re='(?i)\\Users(\\|$)|%USERPROFILE%|%LOCALAPPDATA%|%APPDATA%|%HOMEPATH%|%TMP%|%TEMP%';
                                                           Reason='User profile/AppData is writable';    Severity='High'   },
    @{ Re='(?i)\\(Downloads|Desktop|Documents)(\\|$)';      Reason='Common user-writable folders';       Severity='High'   },
    @{ Re='(?i)\\Public(\\|$)';                             Reason='Public folders are shared/writable'; Severity='Medium' },
    @{ Re='(?i)\\ProgramData(\\|$)';                        Reason='ProgramData often has writable subs';Severity='Medium' }
  )
  foreach ($c in $checks) { if ($PathText -match $c.Re) { return @{ Match=$true; Reason=$c.Reason; Severity=$c.Severity } } }
  if ($PathText -match '(?i)\\Program Files( \(x86\))?(\\|$)' -or $PathText -match '(?i)\\Windows(\\|$)') { return $null }
  return $null
}

# Protected bases (except Windows\Temp)
function Is-ProtectedPath {
  param([string]$ExpandedLocalPath)
  if (-not $ExpandedLocalPath) { return $false }
  if ($ExpandedLocalPath -match '(?i)^[A-Z]:\\Windows\\Temp(\\|$)') { return $false }
  return ($ExpandedLocalPath -match '(?i)^[A-Z]:\\Program Files( \(x86\))?\\') -or
         ($ExpandedLocalPath -match '(?i)^[A-Z]:\\Windows(\\|$|\\.+)')
}

$SeverityScore = @{ High=3; Medium=2; Low=1; Info=0 }

function New-Finding {
  param([string]$Severity,[hashtable]$Props)
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
  param([string]$PathText)
  if (-not $PathText) { return $null }
  # Expand %ENV% tokens using .NET
  $expanded = [Environment]::ExpandEnvironmentVariables($PathText)

  # %OSDRIVE% common macro
  if ($expanded -match '(?i)%OSDRIVE%') {
    $sysDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Root -match '^[A-Z]:\\$'} | Sort-Object Used -Descending | Select-Object -First 1).Root.TrimEnd('\')
    if (-not $sysDrive) { $sysDrive = "$($env:SystemDrive)" }
    $expanded = $expanded -replace '(?i)%OSDRIVE%',$sysDrive
  }

  # Normalize double backslashes in middle (not leading for UNC)
  $expanded = $expanded -replace '(?<!^|\\)\\{2,}','\'
  return $expanded
}

# ----- Local NTFS rights -----

function Get-LocalNtfsRightsForPrincipal {
  <# Returns: 'None','Read','Write','Modify','Full' #>
  param([string]$Path,[string[]]$PrincipalNames)
  try { $acl = Get-Acl -Path $Path -ErrorAction Stop } catch { return 'None' }

  $writeBits = [System.Security.AccessControl.FileSystemRights]::Write,
               [System.Security.AccessControl.FileSystemRights]::Modify,
               [System.Security.AccessControl.FileSystemRights]::FullControl,
               [System.Security.AccessControl.FileSystemRights]::CreateFiles,
               [System.Security.AccessControl.FileSystemRights]::AppendData,
               [System.Security.AccessControl.FileSystemRights]::WriteData,
               [System.Security.AccessControl.FileSystemRights]::Delete,
               [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles

  $max = 'None'
  foreach ($ace in $acl.Access) {
    $aceId = $ace.IdentityReference.Value
    if (-not ($PrincipalNames | Where-Object { $aceId -ieq $_ -or $aceId -match '(?i)\\Users$|^Everyone$|Authenticated Users' })) { continue }

    if ($ace.AccessControlType -eq 'Deny') {
      if ($writeBits | Where-Object { ($ace.FileSystemRights -band $_) -ne 0 }) { return 'None' }
      continue
    }

    $r = $ace.FileSystemRights
    if (($r -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne 0) { return 'Full' }
    if (($r -band [System.Security.AccessControl.FileSystemRights]::Modify) -ne 0)     { return 'Modify' }
    if ($writeBits | Where-Object { ($r -band $_) -ne 0 })                              { if ($max -in @('None','Read')) { $max = 'Write' } }
    if ($max -eq 'None') { $max = 'Read' }
  }
  return $max
}

# ----- UNC share helpers -----

function Get-ShareRoot { param([string]$UncPath) if ($UncPath -notmatch '^(\\\\[^\\]+)\\([^\\]+)') { return $null } "$($Matches[1])\$($Matches[2])" }
function Split-Share   { param([string]$UncPath) if ($UncPath -notmatch '^(\\\\[^\\]+)\\([^\\]+)') { return $null } [pscustomobject]@{ Server=$Matches[1].TrimStart('\'); Share=$Matches[2] } }

function New-CimOrWmi {
  param([string]$ComputerName, [System.Management.Automation.PSCredential]$Credential)
  try {
    $cim = New-CimSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
    return @{ Type='CIM'; Session=$cim }
  } catch {
    try {
      $opt = New-Object System.Management.ConnectionOptions
      if ($Credential) { $opt.Username = $Credential.UserName; $opt.SecurePassword = $Credential.Password }
      $scope = New-Object System.Management.ManagementScope("\\$ComputerName\root\cimv2",$opt)
      $scope.Connect()
      return @{ Type='WMI'; Scope=$scope }
    } catch { return $null }
  }
}

function Get-ShareAclInfo {
  param([string]$Server, [string]$Share, [System.Management.Automation.PSCredential]$Credential)
  $sess = New-CimOrWmi -ComputerName $Server -Credential $Credential
  if (-not $sess) { return $null }

  if ($sess.Type -eq 'CIM') {
    try {
      $acc = Get-SmbShareAccess -CimSession $sess.Session -Name $Share -ErrorAction Stop
      return ($acc | Select-Object @{n='Account';e={$_.AccountName}},
                               @{n='AccessRight';e={$_.AccessRight}},
                               @{n='AccessControlType';e={$_.AccessControlType}})
    } catch { return $null }
  } else {
    try {
      $q = New-Object System.Management.ObjectQuery("SELECT * FROM Win32_LogicalShareSecuritySetting WHERE Name='$Share'")
      $searcher = New-Object System.Management.ManagementObjectSearcher($sess.Scope,$q)
      $obj = $searcher.Get() | Select-Object -First 1
      if (-not $obj) { return $null }
      $sd = ([WMI]$obj.__PATH).GetSecurityDescriptor().Descriptor
      $mapCtrl = @{ 2032127='Full'; 1245631='Change'; 1179817='Read' }
      $aces = @()
      foreach ($dacl in $sd.DACL) {
        $acct = try {
          $sid = New-Object System.Security.Principal.SecurityIdentifier($dacl.Trustee.SID)
          $sid.Translate([System.Security.Principal.NTAccount]).Value
        } catch { $dacl.Trustee.Name }
        $aces += [pscustomobject]@{
          Account           = $acct
          AccessRight       = $mapCtrl[[int]$dacl.AccessMask]
          AccessControlType = (if ($dacl.AceType -eq 0) {'Allow'} else {'Deny'})
        }
      }
      return $aces
    } catch { return $null }
  }
}

function Test-ShareWritableForPrincipal {
  param([array]$ShareAclRows, [string[]]$PrincipalNames)
  if (-not $ShareAclRows) { return $false }
  $writableTags = @('Change','Full','Modify','Write')
  foreach ($p in $PrincipalNames) {
    $hits = $ShareAclRows | Where-Object { $_.Account -ieq $p -or ($_.Account -match '(?i)\\Users$|^Everyone$|Authenticated Users') }
    if ($hits) {
      if ($hits | Where-Object { $_.AccessControlType -eq 'Deny' -and ($writableTags -contains $_.AccessRight) }) { return $false }
      if ($hits | Where-Object { $_.AccessControlType -eq 'Allow' -and ($writableTags -contains $_.AccessRight) }) { return $true }
    }
  }
  return $false
}

function Get-EffectiveNtfsRightsForPrincipal {
  param([string]$Path, [string[]]$PrincipalNames)
  try { $acl = Get-Acl -Path $Path -ErrorAction Stop } catch { return 'None' }

  $writeBits = [System.Security.AccessControl.FileSystemRights]::Write,
               [System.Security.AccessControl.FileSystemRights]::Modify,
               [System.Security.AccessControl.FileSystemRights]::FullControl,
               [System.Security.AccessControl.FileSystemRights]::CreateFiles,
               [System.Security.AccessControl.FileSystemRights]::AppendData,
               [System.Security.AccessControl.FileSystemRights]::WriteData,
               [System.Security.AccessControl.FileSystemRights]::Delete,
               [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles

  $max = 'None'
  foreach ($ace in $acl.Access) {
    $aceId = $ace.IdentityReference.Value
    if (-not ($PrincipalNames | Where-Object { $aceId -ieq $_ -or $aceId -match '(?i)\\Users$|^Everyone$|Authenticated Users' })) { continue }

    if ($ace.AccessControlType -eq 'Deny') {
      if ($writeBits | Where-Object { ($ace.FileSystemRights -band $_) -ne 0 }) { return 'None' }
      continue
    }
    $r = $ace.FileSystemRights
    if (($r -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne 0) { return 'Full' }
    if (($r -band [System.Security.AccessControl.FileSystemRights]::Modify) -ne 0)     { return 'Modify' }
    if ($writeBits | Where-Object { ($r -band $_) -ne 0 })                              { if ($max -in @('None','Read')) { $max = 'Write' } }
    if ($max -eq 'None') { $max = 'Read' }
  }
  return $max
}

function Resolve-BroadPrincipalNames {
  param([string[]]$UserOrGroupSid)
  $names = @()
  foreach ($sid in $UserOrGroupSid) {
    $n = $sid
    if ($sid -match '^S-\d-') { try { $n = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value } catch {} }
    $names += $n
  }
  $names += 'Everyone','Authenticated Users','BUILTIN\Users'
  $names | Select-Object -Unique
}

# ----------------------------- Acquire / Parse XML ----------------------------------

$policyFilePath = $null
$xml = $null

if ([string]::IsNullOrWhiteSpace($Path)) {
  try {
    Write-Verbose "No -Path supplied. Collecting effective AppLocker policy..."
    $xmlText = Get-AppLockerPolicy -Effective -Xml
    if (-not $xmlText) { throw "Get-AppLockerPolicy returned no XML." }

    if (-not $OutPolicyXml -or [string]::IsNullOrWhiteSpace($OutPolicyXml)) {
      $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
      $OutPolicyXml = Join-Path $env:TEMP ("AppLockerPolicy-$env:COMPUTERNAME-$stamp.xml")
    }
    # Ensure directory exists
    $dir = Split-Path -Parent $OutPolicyXml
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

    $xmlText | Out-File -LiteralPath $OutPolicyXml -Encoding UTF8
    Write-Verbose "Saved effective policy to '$OutPolicyXml'."

    [xml]$xml = $xmlText
    $policyFilePath = $OutPolicyXml
  }
  catch {
    throw "Failed to retrieve effective AppLocker policy: $($_.Exception.Message)"
  }
}
else {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "AppLocker policy file not found: $Path"
  }
  [xml]$xml = Get-Content -Raw -LiteralPath $Path
  $policyFilePath = (Resolve-Path -LiteralPath $Path).Path
}

if (-not $xml.AppLockerPolicy) { throw "This does not look like an AppLocker policy XML." }

$results     = New-Object System.Collections.Generic.List[object]
$collections = @($xml.AppLockerPolicy.RuleCollection)
if (-not $collections -or $collections.Count -eq 0) { $collections = @($xml.SelectNodes('//RuleCollection')) }

# ----------------------------- Audit --------------------------------------

foreach ($col in $collections) {
  $colType = $col.Type
  if (-not $colType) { if ($col.FilePathRule -or $col.FilePublisherRule -or $col.FileHashRule) { $colType = '(Unknown)' } }

  $enf = $col.EnforcementMode; if (-not $enf) { $enf = 'NotConfigured' }
  switch -Regex ($enf) {
    'NotConfigured' {
      $results.Add( (New-Finding -Severity 'High' -Props @{
        Collection     = $colType; RuleType='(collection)'; Reason="Collection '$colType' is NotConfigured → default-allow for this type."
        Recommendation = "Set EnforcementMode='Enabled' for '$colType' (or 'AuditOnly' during pilot)."
      }) )
    }
    '^AuditOnly$' {
      $results.Add( (New-Finding -Severity 'High' -Props @{
        Collection     = $colType; RuleType='(collection)'; Reason="Collection '$colType' is AuditOnly (no blocking)."
        Recommendation = "Switch '$colType' to 'Enabled'. Note: Script collection in AuditOnly will not enforce Constrained Language Mode."
      }) )
    }
  }

  $allRules = @()
  if ($col.FilePathRule)      { $allRules += @($col.FilePathRule) }
  if ($col.FilePublisherRule) { $allRules += @($col.FilePublisherRule) }
  if ($col.FileHashRule)      { $allRules += @($col.FileHashRule) }

  foreach ($r in $allRules) {
    $ruleType   = $r.NodeName
    $action     = [string]$r.Action
    $principal  = [string]$r.UserOrGroupSid
    $principalN = Resolve-SidOrName $principal
    $isBroad    = Is-BroadPrincipal $principal
    $isAdmin    = Is-AdminPrincipal $principal

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
        if ($exceptionCount -gt 0 -and $score -gt 0) { $score -= 1 }
      }

      # ----- Local NTFS evaluation -----
      $expanded   = Expand-PathMacros $condText
      $isLocalPath = $expanded -match '^[A-Za-z]:\\'
      $hasWildcard = $expanded -match '[\*\?]'
      if ($isLocalPath -and -not $hasWildcard) {
        $broadNames = Resolve-BroadPrincipalNames @($principal)
        if (Test-Path -LiteralPath $expanded) {
          $localNtfsRight = Get-LocalNtfsRightsForPrincipal -Path $expanded -PrincipalNames $broadNames
          if ($localNtfsRight -in @('Write','Modify','Full')) {
            $results.Add( (New-Finding -Severity 'High' -Props @{
              Collection=$colType; RuleType=$ruleType; Action=$action; Principal=$principalN; RuleName=[string]$r.Name
              ConditionType='Path'; Condition=$condText
              Reason="Local NTFS grants $localNtfsRight to broad principals on $expanded"
              Recommendation="Harden NTFS ACL; remove write/modify for broad groups and restrict to specific app/service groups."
            }) )
          }
        } else {
          $results.Add( (New-Finding -Severity 'Info' -Props @{
            Collection=$colType; RuleType=$ruleType; Action=$action; Principal=$principalN; RuleName=[string]$r.Name
            ConditionType='Path'; Condition=$condText
            Reason="Local path '$expanded' does not exist on this system (skipped NTFS check)"
            Recommendation="Validate on target systems where the path exists."
          }) )
        }
      } elseif ($isLocalPath -and $hasWildcard) {
        # Try parent directory if obvious (heuristic)
        $parent = Split-Path -Path $expanded -Parent -ErrorAction SilentlyContinue
        if ($parent -and (Test-Path -LiteralPath $parent)) {
          $broadNames = Resolve-BroadPrincipalNames @($principal)
          $ntfsParent = Get-LocalNtfsRightsForPrincipal -Path $parent -PrincipalNames $broadNames
          if ($ntfsParent -in @('Write','Modify','Full')) {
            $results.Add( (New-Finding -Severity 'Medium' -Props @{
              Collection=$colType; RuleType=$ruleType; Action=$action; Principal=$principalN; RuleName=[string]$r.Name
              ConditionType='Path'; Condition=$condText
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
          $serverName  = $split.Server
          $shareName   = $split.Share
          $broadNames  = Resolve-BroadPrincipalNames @($principal)
          $shareAcl    = Get-ShareAclInfo -Server $serverName -Share $shareName -Credential $Credential
          $shareWritable = $false
          if ($shareAcl) {
            $shareWritable = Test-ShareWritableForPrincipal -ShareAclRows $shareAcl -PrincipalNames $broadNames
          } else {
            $results.Add( (New-Finding -Severity 'Info' -Props @{
              Collection=$colType; RuleType=$ruleType; Action=$action; Principal=$principalN; RuleName=[string]$r.Name
              ConditionType='Path'; Condition=$condText
              Reason="Could not read share ACL on \\$serverName\$shareName (insufficient rights or remote management disabled)"
              Recommendation="Run with credentials that can query share permissions or audit directly on the file server."
            }) )
          }

          if ($shareWritable) {
            $results.Add( (New-Finding -Severity 'High' -Props @{
              Collection=$colType; RuleType=$ruleType; Action=$action; Principal=$principalN; RuleName=[string]$r.Name
              ConditionType='Path'; Condition=$condText
              Reason="Share ACL on \\$serverName\$shareName grants Change/Full to broad principals"
              Recommendation="Tighten SMB share permissions: remove Change/Full for Everyone/Auth Users/Users."
            }) )
          }

          # NTFS on the UNC path itself (skip wildcards)
          if ($condText -notmatch '[\*\?]') {
            $ntfsRight = Get-EffectiveNtfsRightsForPrincipal -Path $condText -PrincipalNames $broadNames
            if ($ntfsRight -in @('Write','Modify','Full')) {
              $results.Add( (New-Finding -Severity 'High' -Props @{
                Collection=$colType; RuleType=$ruleType; Action=$action; Principal=$principalN; RuleName=[string]$r.Name
                ConditionType='Path'; Condition=$condText
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
      $product   = [string]$c.ProductName
      $binary    = [string]$c.BinaryName
      $range     = $c.BinaryVersionRange
      $low       = if ($range) { $range.LowSection; if (-not $low) { $low = $range.Low } }
      $high      = if ($range) { $range.HighSection; if (-not $high){ $high= $range.High } }
      $condText  = "Publisher='$publisher'; Product='$product'; Binary='$binary'; VersionRange=[$low,$high]"

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
        if (Is-BroadPrincipal $principal -and -not (Is-AdminPrincipal $principal)) {
          $reasons += "Principal is broad (Everyone/Authenticated Users/Users)"
          $rec     += "Restrict the principal to a minimal, purpose-built group."
          $score = [Math]::Max($score, $SeverityScore['Medium'])
        }
        if ($exceptionCount -gt 0 -and $score -gt 0) { $score -= 1 }
      }

      if ($score -ge 0 -and $reasons.Count -gt 0) {
        $sev = ($SeverityScore.GetEnumerator() | Sort-Object Value -Descending | Where-Object { $_.Value -le $score } | Select-Object -First 1).Key
        if (-not $sev) { $sev = 'Info' }
        $results.Add( (New-Finding -Severity $sev -Props @{
          Collection=$colType; RuleType=$ruleType; Action=$action; Principal=$principalN; RuleName=[string]$r.Name
          ConditionType=$condType; Condition=$condText
          Reason=($reasons -join '; ')
          Recommendation= (($rec | Select-Object -Unique) -join ' ')
        }) )
      }

    } elseif ($r.Conditions.FileHashCondition) {
      $condType = 'Hash'
      $hashObjs = @($r.Conditions.FileHashCondition.FileHash)
      $hashList = if ($hashObjs) { ($hashObjs | ForEach-Object { $_.InputFileName }) -join '; ' } else { '<no-hash-names>' }
      $condText = "Hashes: $hashList"
      if ($action -match 'Allow' -and (Is-BroadPrincipal $principal) -and -not (Is-AdminPrincipal $principal)) {
        $results.Add( (New-Finding -Severity 'Low' -Props @{
          Collection=$colType; RuleType=$ruleType; Action=$action; Principal=$principalN; RuleName=[string]$r.Name
          ConditionType=$condType; Condition=$condText
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
          (Is-ProtectedPath -ExpandedLocalPath $expanded)) {
        $ntfsText = if ($null -eq $localNtfsRight) { 'Unknown' } else { $localNtfsRight }
        $reasons = @("Broad principal allowed, but target is in a protected location and not writable by broad principals (NTFS: $ntfsText)")
        $rec = @("No change needed if the file remains locked down; consider Publisher/Hash rules if you want defense-in-depth.")
        $sev = 'Info'
        $results.Add( (New-Finding -Severity $sev -Props @{
          Collection=$colType; RuleType=$ruleType; Action=$action; Principal=$principalN; RuleName=[string]$r.Name
          ConditionType=$condType; Condition=$condText
          Reason=($reasons -join '; ')
          Recommendation=(($rec | Select-Object -Unique) -join ' ')
        }) )
        $downgraded = $true
      }

      if (-not $downgraded) {
        $sev = ($SeverityScore.GetEnumerator() | Sort-Object Value -Descending | Where-Object { $_.Value -le $score } | Select-Object -First 1).Key
        if (-not $sev) { $sev = 'Info' }
        $results.Add( (New-Finding -Severity $sev -Props @{
          Collection=$colType; RuleType=$ruleType; Action=$action; Principal=$principalN; RuleName=[string]$r.Name
          ConditionType=$condType; Condition=$condText
          Reason=($reasons -join '; ')
          Recommendation=(($rec | Select-Object -Unique) -join ' ')
        }) )
      }
    }

  } # end foreach rule
} # end foreach collection

# ----------------------------- Output -------------------------------------

if ($OutCsv) {
  try {
    $results | Sort-Object Severity,Collection | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
    Write-Verbose "Wrote CSV to $OutCsv"
  } catch {
    Write-Warning "Failed writing CSV: $($_.Exception.Message)"
  }
}

if ($AsJson) {
  $results | ConvertTo-Json -Depth 6
} else {
  $results | Sort-Object @{Expression='Severity';Descending=$true}, Collection, RuleType, RuleName
}

}
