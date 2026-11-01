<#
.SYNOPSIS
    Prepares a tenant for Microsoft Purview Insider Risk Management and verifies an Insider Risk policy.

.DESCRIPTION
    Automates the supported parts of an Insider Risk Management deployment:

      1. Checks that unified audit logging is enabled (and optionally turns it on).
      2. Adds users to the built-in Insider Risk Management role groups.
      3. Checks which Insider Risk policy cmdlets your tenant exposes.
      4. Verifies that a named Insider Risk policy exists and exports its configuration to JSON.

    Microsoft does not currently provide a documented, supported cmdlet for creating Insider Risk
    policies. Create the policy in the Microsoft Purview portal (see the accompanying blog post),
    then run this script to verify it. If your tenant exposes New-InsiderRiskPolicy, the script
    reports it, but it does not use it.

    The script is idempotent: existing role group members are skipped. Use -WhatIf to preview changes.

.PARAMETER AdminUpn
    Users to add to the 'Insider Risk Management Admins' role group (configure policies and settings).

.PARAMETER AnalystUpn
    Users to add to the 'Insider Risk Management Analysts' role group (triage alerts, pseudonymised view).

.PARAMETER InvestigatorUpn
    Users to add to the 'Insider Risk Management Investigators' role group (investigate cases and content).

.PARAMETER AuditorUpn
    Users to add to the 'Insider Risk Management Auditors' role group (view and export the IRM audit log).

.PARAMETER ApproverUpn
    Users to add to the 'Insider Risk Management Approvers' role group (approve forensic evidence capture).

.PARAMETER PolicyName
    The name of the Insider Risk policy to verify. Defaults to the policy created in the blog walkthrough.

.PARAMETER ExportPath
    Folder for the policy configuration export. Defaults to the current folder.

.PARAMETER EnableAuditing
    Turns on unified audit log ingestion if it is off. Without this switch the script only reports the status.

.PARAMETER SkipAuditCheck
    Skips the Exchange Online connection and audit log check.

.EXAMPLE
    .\Invoke-InsiderRiskSetup.ps1 -AdminUpn admin@contoso.com -AnalystUpn analyst1@contoso.com,analyst2@contoso.com -WhatIf

    Previews the role group changes without making them.

.EXAMPLE
    .\Invoke-InsiderRiskSetup.ps1 -AdminUpn admin@contoso.com -InvestigatorUpn investigator@contoso.com -EnableAuditing

    Turns on auditing if needed, assigns roles and verifies the default policy.

.EXAMPLE
    .\Invoke-InsiderRiskSetup.ps1 -PolicyName 'Contoso - Data theft by departing users' -SkipAuditCheck

    Only verifies and exports the named policy.

.NOTES
    Author:   Seán O'Farrell
    Website:  https://cloud-secure.ai/
    Version:  1.0
    Requires: ExchangeOnlineManagement module 3.2 or later
              Run as a Global Administrator, Compliance Administrator or Organization Management member
    Role group changes can take up to 30 minutes to apply.
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [string[]] $AdminUpn        = @(),
    [string[]] $AnalystUpn      = @(),
    [string[]] $InvestigatorUpn = @(),
    [string[]] $AuditorUpn      = @(),
    [string[]] $ApproverUpn     = @(),

    [string] $PolicyName = 'Contoso - Data theft by departing users',

    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string] $ExportPath = (Get-Location).Path,

    [switch] $EnableAuditing,
    [switch] $SkipAuditCheck
)

$ErrorActionPreference = 'Stop'

# Summary counters
$summary = [ordered]@{
    MembersAdded   = 0
    MembersSkipped = 0
    MembersFailed  = 0
    AuditChanged   = $false
    PolicyFound    = $false
}

# Role group display names as shown in the Microsoft Purview portal
$roleAssignments = [ordered]@{
    'Insider Risk Management Admins'        = $AdminUpn
    'Insider Risk Management Analysts'      = $AnalystUpn
    'Insider Risk Management Investigators' = $InvestigatorUpn
    'Insider Risk Management Auditors'      = $AuditorUpn
    'Insider Risk Management Approvers'     = $ApproverUpn
}

function Write-Step  ([string] $Message) { Write-Host "`n🔷 $Message" -ForegroundColor Cyan }
function Write-Ok    ([string] $Message) { Write-Host "   ✅ $Message" -ForegroundColor Green }
function Write-Skip  ([string] $Message) { Write-Host "   ⏭️  $Message" -ForegroundColor DarkGray }
function Write-Warn  ([string] $Message) { Write-Host "   ⚠️  $Message" -ForegroundColor Yellow }
function Write-Fail  ([string] $Message) { Write-Host "   ❌ $Message" -ForegroundColor Red }

#region Prerequisites
Write-Step 'Checking prerequisites'
try {
    $module = Get-Module -ListAvailable -Name ExchangeOnlineManagement |
        Sort-Object Version -Descending | Select-Object -First 1
    if (-not $module) {
        throw 'ExchangeOnlineManagement is not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }
    if ($module.Version -lt [version]'3.2.0') {
        Write-Warn "ExchangeOnlineManagement $($module.Version) found. Version 3.2 or later is recommended."
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Write-Ok "ExchangeOnlineManagement $($module.Version) loaded"
}
catch {
    Write-Fail $_.Exception.Message
    return
}
#endregion

#region Audit log
if (-not $SkipAuditCheck) {
    Write-Step 'Checking unified audit logging (Exchange Online)'
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        $auditConfig = Get-AdminAuditLogConfig -ErrorAction Stop

        if ($auditConfig.UnifiedAuditLogIngestionEnabled) {
            Write-Ok 'Unified audit logging is enabled'
        }
        elseif ($EnableAuditing) {
            if ($PSCmdlet.ShouldProcess('Tenant', 'Enable unified audit log ingestion')) {
                Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ErrorAction Stop
                $summary.AuditChanged = $true
                Write-Ok 'Unified audit logging turned on. It can take a few hours to start recording.'
            }
        }
        else {
            Write-Warn 'Unified audit logging is OFF. Insider Risk Management needs it. Re-run with -EnableAuditing.'
        }
    }
    catch {
        Write-Fail "Audit check failed: $($_.Exception.Message)"
    }
    finally {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    }
}
else {
    Write-Step 'Skipping audit log check'
}
#endregion

#region Connect to Security & Compliance PowerShell
Write-Step 'Connecting to Security & Compliance PowerShell'
try {
    Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop
    Write-Ok 'Connected'
}
catch {
    Write-Fail "Connection failed: $($_.Exception.Message)"
    return
}
#endregion

try {
    #region Role groups
    Write-Step 'Assigning Insider Risk Management role groups'
    $allRoleGroups = Get-RoleGroup -ErrorAction Stop

    foreach ($displayName in $roleAssignments.Keys) {
        $members = @($roleAssignments[$displayName] | Where-Object { $_ })
        if ($members.Count -eq 0) { continue }

        $roleGroup = $allRoleGroups | Where-Object { $_.DisplayName -eq $displayName } | Select-Object -First 1
        if (-not $roleGroup) {
            Write-Fail "Role group '$displayName' not found in this tenant"
            $summary.MembersFailed += $members.Count
            continue
        }

        # Collect every identifier of existing members so the comparison is reliable
        $existing = @(Get-RoleGroupMember -Identity $roleGroup.Identity -ErrorAction Stop |
            ForEach-Object { $_.PrimarySmtpAddress; $_.WindowsLiveID; $_.Name } |
            Where-Object { $_ } | ForEach-Object { $_.ToString().ToLowerInvariant() })

        foreach ($upn in $members) {
            if ($existing -contains $upn.ToLowerInvariant()) {
                Write-Skip "$upn is already in '$displayName'"
                $summary.MembersSkipped++
                continue
            }
            try {
                if ($PSCmdlet.ShouldProcess($upn, "Add to role group '$displayName'")) {
                    Add-RoleGroupMember -Identity $roleGroup.Identity -Member $upn -ErrorAction Stop
                    Write-Ok "Added $upn to '$displayName'"
                    $summary.MembersAdded++
                }
            }
            catch {
                Write-Fail "Could not add $upn to '$displayName': $($_.Exception.Message)"
                $summary.MembersFailed++
            }
        }
    }
    if (($roleAssignments.Values | ForEach-Object { $_ } | Where-Object { $_ }).Count -eq 0) {
        Write-Skip 'No users supplied - role groups unchanged'
    }
    #endregion

    #region Policy cmdlet availability
    Write-Step 'Checking Insider Risk policy cmdlets exposed by this tenant'
    $irmCommands = Get-Command -Name '*InsiderRisk*' -ErrorAction SilentlyContinue | Sort-Object Name
    if ($irmCommands) {
        Write-Ok ("Available: {0}" -f (($irmCommands.Name) -join ', '))
    }
    else {
        Write-Warn 'No Insider Risk cmdlets are exposed in this session'
    }
    if ($irmCommands.Name -contains 'New-InsiderRiskPolicy') {
        Write-Warn 'New-InsiderRiskPolicy is present but undocumented. Create policies in the Purview portal.'
    }
    #endregion

    #region Verify and export the policy
    Write-Step "Verifying policy '$PolicyName'"
    if ($irmCommands.Name -contains 'Get-InsiderRiskPolicy') {
        try {
            $policy = Get-InsiderRiskPolicy -ErrorAction Stop | Where-Object { $_.Name -eq $PolicyName }
            if ($policy) {
                $summary.PolicyFound = $true
                Write-Ok "Found '$PolicyName'"
                $policy | Format-List Name, InsiderRiskScenario, Enabled, WhenCreatedUTC, WhenChangedUTC -ErrorAction SilentlyContinue

                $safeName   = ($PolicyName -replace '[^\w\-]+', '-').Trim('-')
                $exportFile = Join-Path $ExportPath ("{0}_{1:yyyyMMdd-HHmm}.json" -f $safeName, (Get-Date))
                $policy | ConvertTo-Json -Depth 6 | Out-File -FilePath $exportFile -Encoding utf8
                Write-Ok "Configuration exported to $exportFile"
            }
            else {
                Write-Warn "No policy named '$PolicyName'. Create it in the Purview portal and re-run."
            }
        }
        catch {
            Write-Fail "Policy lookup failed: $($_.Exception.Message)"
        }
    }
    else {
        Write-Warn 'Get-InsiderRiskPolicy is not available. Verify the policy in the Purview portal.'
    }
    #endregion
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}

#region Summary
Write-Step 'Summary'
Write-Host ("   👥 Members added:   {0}" -f $summary.MembersAdded)
Write-Host ("   ⏭️  Members skipped: {0}" -f $summary.MembersSkipped)
Write-Host ("   ❌ Members failed:  {0}" -f $summary.MembersFailed)
Write-Host ("   📋 Auditing changed: {0}" -f $summary.AuditChanged)
Write-Host ("   🛡️  Policy found:    {0}" -f $summary.PolicyFound)
if ($summary.MembersAdded -gt 0) {
    Write-Host "`n   ⏱️  Role group changes can take up to 30 minutes to apply." -ForegroundColor Yellow
}
#endregion
