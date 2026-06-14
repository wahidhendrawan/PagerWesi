[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet("Audit", "Plan", "Apply")]
    [string]$Mode = "Audit",
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if ($Mode -eq "Apply" -and -not $isAdmin) { throw "Apply mode requires Administrator privileges." }

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result($Id, $Title, $Status, $Severity, $Evidence, $Remediation = "") {
    $results.Add([pscustomobject]@{
        control_id = $Id; title = $Title; status = $Status; severity = $Severity
        evidence = $Evidence; remediation = $Remediation
    })
}
function Invoke-Change([string]$Description, [scriptblock]$Action) {
    if ($Mode -eq "Plan") { Write-Host "[PLAN] $Description"; return }
    if ($Mode -eq "Apply" -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, $Description)) { & $Action }
}

$disabledProfiles = Get-NetFirewallProfile | Where-Object Enabled -eq $false
Add-Result "WINDOWS-FW-001" "Windows Firewall is enabled" `
    $(if ($disabledProfiles) { "fail" } else { "pass" }) "high" `
    "Disabled profiles: $($disabledProfiles.Name -join ', ')" "Enable all firewall profiles."

$smb = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
$smbDisabled = -not $smb -or $smb.State -ne "Enabled"
Add-Result "WINDOWS-SMB-001" "SMBv1 is disabled" $(if ($smbDisabled) { "pass" } else { "fail" }) `
    "critical" "State=$($smb.State)" "Disable the SMB1Protocol optional feature."

$guest = Get-LocalUser | Where-Object SID -Like "*-501"
$guestDisabled = -not $guest -or -not $guest.Enabled
Add-Result "WINDOWS-AUTH-001" "Built-in guest account is disabled" `
    $(if ($guestDisabled) { "pass" } else { "fail" }) "high" "Enabled=$($guest.Enabled)" `
    "Disable the account with RID 501."

$logonAudit = auditpol /get /subcategory:"Logon" /r | ConvertFrom-Csv
$logonValue = ($logonAudit | Select-Object -First 1).'Inclusion Setting'
$auditEnabled = $logonValue -match "Success" -and $logonValue -match "Failure"
Add-Result "WINDOWS-AUDIT-001" "Logon success and failure auditing is enabled" `
    $(if ($auditEnabled) { "pass" } else { "fail" }) "medium" "Setting=$logonValue" `
    "Enable success and failure auditing for Logon."

if ($Mode -ne "Audit") {
    Invoke-Change "Enable all Windows Firewall profiles" { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True }
    if (-not $smbDisabled) {
        Invoke-Change "Disable SMBv1" { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart }
    }
    if (-not $guestDisabled) {
        Invoke-Change "Disable built-in guest account" { Disable-LocalUser -SID $guest.SID }
    }
    Invoke-Change "Configure advanced audit policy" {
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
    }
}

$results | ForEach-Object { Write-Host "[$($_.status.ToUpper())] $($_.control_id) $($_.title): $($_.evidence)" }
if ($OutputPath) { $results | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 $OutputPath }
if ($results.status -contains "fail") { exit 1 }
