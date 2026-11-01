<#
.SYNOPSIS
    LAB ONLY. Simulates a departing user exfiltrating data, to test Microsoft Purview Insider Risk Management policies.

.DESCRIPTION
    Generates the kind of activity a "Data theft by departing users" policy is designed to detect, so you
    can prove a policy works and capture the resulting alert. Run it as the TEST USER, on a Windows device
    onboarded to Microsoft Defender for Endpoint, in a LAB TENANT.

    The simulation runs in stages, mirroring the sequences Insider Risk Management looks for
    (download -> obfuscate -> exfiltrate -> delete):

      Seed        Creates test files containing dummy sensitive data and uploads them to a SharePoint site
      Download    Downloads the files from SharePoint to the device
      Obfuscate   Compresses the files into an archive and renames it to hide the file type
      Exfiltrate  Copies the archive to removable media and/or a personal cloud sync folder
      Email       Emails the files as attachments to an external address (only if -ExternalRecipient is set)
      Cleanup     Deletes the local copies and sends the SharePoint folder to the recycle bin

    Every action is written to a CSV log so you can match it against the alert timeline.

    BEFORE YOU RUN IT
      - Use a dedicated test account in a lab tenant. Never run this in production.
      - Bring the test user into scope: use "Start scoring activity for users" on the Insider Risk
        Management Policies page, or upload an HR connector resignation record for them.
      - Alerts can take up to 24 hours to appear.

    The test data is clearly marked and uses published test values, but it will still match sensitive
    information types. That is the point - it raises the risk score.

.PARAMETER LabTenantDomain
    A verified domain of your lab tenant (for example contosolab.onmicrosoft.com). The script stops if the
    signed-in tenant does not own this domain. This is a guard against running it in the wrong tenant.

.PARAMETER IUnderstandThisIsALab
    Required. Confirms you are running this in a lab tenant with a test account.

.PARAMETER SiteUrl
    SharePoint site the test files are uploaded to and downloaded from, for example
    https://contosolab.sharepoint.com/sites/Projects

.PARAMETER FileCount
    Number of test files to generate. More files produce a stronger signal. Default 40.

.PARAMETER WorkingPath
    Local folder for downloaded files and the archive. Default: a folder under the user's temp directory.

.PARAMETER RemovableMediaPath
    Path on a USB drive (for example E:\). Copying here triggers removable media indicators.

.PARAMETER PersonalCloudPath
    A personal cloud sync folder on the device (for example a personal Dropbox or Google Drive folder).

.PARAMETER ExternalRecipient
    External email address to send attachments to. Leave empty to skip the Email stage.

.PARAMETER Stages
    Stages to run. Defaults to all of them. The Email stage is skipped without -ExternalRecipient.

.PARAMETER FolderName
    SharePoint folder to use. Defaults to a new IRMSIM-<timestamp> folder. Pass the folder name from an
    earlier Seed run to download those files as the test user.

.PARAMETER LogPath
    Folder for the CSV activity log. Defaults to the current folder.

.EXAMPLE
    .\Invoke-InsiderRiskSimulation.ps1 -LabTenantDomain contosolab.onmicrosoft.com -IUnderstandThisIsALab `
        -SiteUrl https://contosolab.sharepoint.com/sites/Projects -RemovableMediaPath E:\ -WhatIf

    Shows what the full simulation would do, without doing it.

.EXAMPLE
    .\Invoke-InsiderRiskSimulation.ps1 -LabTenantDomain contosolab.onmicrosoft.com -IUnderstandThisIsALab `
        -SiteUrl https://contosolab.sharepoint.com/sites/Projects `
        -RemovableMediaPath E:\ -PersonalCloudPath "$env:USERPROFILE\Dropbox" `
        -ExternalRecipient my.personal.address@outlook.com

    Runs every stage.

.EXAMPLE
    .\Invoke-InsiderRiskSimulation.ps1 -LabTenantDomain contosolab.onmicrosoft.com -IUnderstandThisIsALab `
        -SiteUrl https://contosolab.sharepoint.com/sites/Projects -Stages Seed

    Seeds the test files only - for example as an admin - so the test user can run the remaining stages later.

.NOTES
    Author:   Seán O'Farrell
    Website:  https://cloud-secure.ai/
    Version:  1.0
    Requires: Microsoft.Graph.Authentication module
              Delegated Graph permissions: Sites.ReadWrite.All, Files.ReadWrite.All, Mail.Send (Email stage)
    LAB USE ONLY. Provided as is, without warranty.
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')]
    [string] $LabTenantDomain,

    [switch] $IUnderstandThisIsALab,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://[^/]+\.sharepoint\.com/sites/[^/]+')]
    [string] $SiteUrl,

    [ValidateRange(5, 500)]
    [int] $FileCount = 40,

    [string] $WorkingPath = (Join-Path ([IO.Path]::GetTempPath()) 'IRM-Simulation'),

    [string] $RemovableMediaPath,

    [string] $PersonalCloudPath,

    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string] $ExternalRecipient,

    [ValidateSet('Seed', 'Download', 'Obfuscate', 'Exfiltrate', 'Email', 'Cleanup')]
    [string[]] $Stages = @('Seed', 'Download', 'Obfuscate', 'Exfiltrate', 'Email', 'Cleanup'),

    [ValidatePattern('^[\w-]+$')]
    [string] $FolderName,

    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string] $LogPath = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'

function Write-Step ([string] $Message) { Write-Host "`n🔷 $Message" -ForegroundColor Cyan }
function Write-Ok   ([string] $Message) { Write-Host "   ✅ $Message" -ForegroundColor Green }
function Write-Skip ([string] $Message) { Write-Host "   ⏭️  $Message" -ForegroundColor DarkGray }
function Write-Warn ([string] $Message) { Write-Host "   ⚠️  $Message" -ForegroundColor Yellow }
function Write-Fail ([string] $Message) { Write-Host "   ❌ $Message" -ForegroundColor Red }

$runId      = 'IRMSIM-{0:yyyyMMdd-HHmmss}' -f (Get-Date)
$folderName = if ($FolderName) { $FolderName } else { $runId }
$activity   = [System.Collections.Generic.List[object]]::new()
$summary    = [ordered]@{ Succeeded = 0; Skipped = 0; Failed = 0 }

function Add-Activity ([string] $Stage, [string] $Action, [string] $Target, [string] $Result) {
    $activity.Add([pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        RunId        = $runId
        Stage        = $Stage
        Action       = $Action
        Target       = $Target
        Result       = $Result
    })
    switch ($Result) { 'Success' { $summary.Succeeded++ } 'Skipped' { $summary.Skipped++ } default { $summary.Failed++ } }
}

#region Banner and guardrails
Write-Host ''
Write-Host '  ┌──────────────────────────────────────────────────────────────┐' -ForegroundColor Red
Write-Host '  │  🧪 INSIDER RISK SIMULATION - LAB TENANTS AND TEST USERS ONLY │' -ForegroundColor Red
Write-Host '  └──────────────────────────────────────────────────────────────┘' -ForegroundColor Red

if (-not $IUnderstandThisIsALab) {
    Write-Fail 'You must pass -IUnderstandThisIsALab. Stopping.'
    return
}
if ('Email' -in $Stages -and -not $ExternalRecipient) {
    $Stages = $Stages | Where-Object { $_ -ne 'Email' }
}
#endregion

#region Connect to Microsoft Graph and confirm the tenant
Write-Step 'Connecting to Microsoft Graph'
try {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $scopes = @('User.Read', 'Sites.ReadWrite.All', 'Files.ReadWrite.All')
    if ('Email' -in $Stages) { $scopes += 'Mail.Send' }
    Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop

    $context = Get-MgContext
    $org     = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/organization?$select=displayName,verifiedDomains'
    $domains = @($org.value[0].verifiedDomains | ForEach-Object { $_.name.ToLowerInvariant() })

    if ($domains -notcontains $LabTenantDomain.ToLowerInvariant()) {
        throw "Signed-in tenant '$($org.value[0].displayName)' does not own '$LabTenantDomain'. Stopping to protect the wrong tenant."
    }
    Write-Ok "Signed in as $($context.Account) to lab tenant '$($org.value[0].displayName)'"
}
catch {
    Write-Fail $_.Exception.Message
    return
}
#endregion

try {
    # Resolve the site and its default document library
    $siteUri = [uri]$SiteUrl
    $site    = Invoke-MgGraphRequest -Method GET -Uri ("v1.0/sites/{0}:{1}" -f $siteUri.Host, $siteUri.AbsolutePath.TrimEnd('/'))
    $driveId = (Invoke-MgGraphRequest -Method GET -Uri "v1.0/sites/$($site.id)/drive").id
    Write-Ok "Using site '$($site.displayName)'"

    $downloadPath = Join-Path $WorkingPath $folderName
    $seedPath     = Join-Path $WorkingPath "$folderName-seed"
    $archivePath  = Join-Path $WorkingPath "$folderName.zip"
    $disguised    = Join-Path $WorkingPath "holiday-photos-$((Get-Date).ToString('yyyyMMdd')).dat"

    #region Stage: Seed
    if ('Seed' -in $Stages) {
        Write-Step "Seed - creating $FileCount test files and uploading them to SharePoint"
        if ($PSCmdlet.ShouldProcess($SiteUrl, "Upload $FileCount test files to /$folderName")) {
            New-Item -Path $seedPath -ItemType Directory -Force | Out-Null

            # Published test values only. Clearly labelled as test data.
            $testCards = @('4111 1111 1111 1111', '5555 5555 5555 4444', '3782 822463 10005')
            $testIbans = @('IE29 AIBK 9311 5212 3456 78', 'GB82 WEST 1234 5698 7654 32')
            $docTypes  = @('Customer-List', 'Pricing-Model', 'Board-Pack', 'Payroll-Extract', 'Product-Roadmap')

            for ($n = 1; $n -le $FileCount; $n++) {
                $name = '{0}-{1:D3}.txt' -f $docTypes[$n % $docTypes.Count], $n
                $file = Join-Path $seedPath $name
                $body = @(
                    'CONTOSO CONFIDENTIAL - TEST DATA FOR INSIDER RISK SIMULATION - NOT REAL'
                    "Simulation run: $runId"
                    ''
                    'Customer name,Card number,IBAN,Account manager'
                )
                for ($r = 1; $r -le 15; $r++) {
                    $body += 'Test Customer {0},{1},{2},Contoso Sales' -f $r, $testCards[$r % $testCards.Count], $testIbans[$r % $testIbans.Count]
                }
                $body | Set-Content -Path $file -Encoding UTF8

                try {
                    $uploadUri = "v1.0/drives/$driveId/root:/$folderName/$($name):/content"
                    Invoke-MgGraphRequest -Method PUT -Uri $uploadUri -InputFilePath $file -ContentType 'text/plain' | Out-Null
                    Add-Activity 'Seed' 'Upload' "$folderName/$name" 'Success'
                }
                catch {
                    Write-Fail "Upload failed for $($name): $($_.Exception.Message)"
                    Add-Activity 'Seed' 'Upload' "$folderName/$name" 'Failed'
                }
            }
            Remove-Item -Path $seedPath -Recurse -Force
            Write-Ok "Uploaded test files to /$folderName"
            Write-Host "   📁 To download these as the test user later, pass -FolderName $folderName" -ForegroundColor Yellow
        }
    }
    #endregion

    #region Stage: Download
    if ('Download' -in $Stages) {
        Write-Step 'Download - downloading the files from SharePoint to this device'
        if ($PSCmdlet.ShouldProcess($SiteUrl, "Download files from /$folderName")) {
            New-Item -Path $downloadPath -ItemType Directory -Force | Out-Null
            $children = (Invoke-MgGraphRequest -Method GET -Uri "v1.0/drives/$driveId/root:/$($folderName):/children?`$top=999").value
            if (-not $children) {
                Write-Warn "No files found in /$folderName. Run the Seed stage first."
                Add-Activity 'Download' 'Download' "/$folderName" 'Skipped'
            }
            foreach ($item in $children) {
                try {
                    $target = Join-Path $downloadPath $item.name
                    Invoke-MgGraphRequest -Method GET -Uri "v1.0/drives/$driveId/items/$($item.id)/content" -OutputFilePath $target
                    Add-Activity 'Download' 'Download' $item.name 'Success'
                }
                catch {
                    Add-Activity 'Download' 'Download' $item.name 'Failed'
                }
            }
            Write-Ok "Downloaded $(@($children).Count) files to $downloadPath"
        }
    }
    #endregion

    #region Stage: Obfuscate
    if ('Obfuscate' -in $Stages) {
        Write-Step 'Obfuscate - compressing the files and disguising the archive'
        if (-not (Test-Path $downloadPath)) {
            Write-Warn 'Nothing to compress. Run the Download stage first.'
            Add-Activity 'Obfuscate' 'Compress' $downloadPath 'Skipped'
        }
        elseif ($PSCmdlet.ShouldProcess($downloadPath, 'Compress and rename to a misleading .dat file')) {
            Compress-Archive -Path (Join-Path $downloadPath '*') -DestinationPath $archivePath -Force
            Add-Activity 'Obfuscate' 'Compress' $archivePath 'Success'
            Move-Item -Path $archivePath -Destination $disguised -Force
            Add-Activity 'Obfuscate' 'Rename' $disguised 'Success'
            Write-Ok "Archive disguised as $(Split-Path $disguised -Leaf)"
        }
    }
    #endregion

    #region Stage: Exfiltrate
    if ('Exfiltrate' -in $Stages) {
        Write-Step 'Exfiltrate - copying the archive off the device'
        $source = if (Test-Path $disguised) { $disguised } elseif (Test-Path $downloadPath) { $downloadPath } else { $null }
        if (-not $source) {
            Write-Warn 'Nothing to exfiltrate. Run the Download stage first.'
            Add-Activity 'Exfiltrate' 'Copy' '-' 'Skipped'
        }
        else {
            foreach ($dest in @(
                    @{ Label = 'Removable media'; Path = $RemovableMediaPath },
                    @{ Label = 'Personal cloud';  Path = $PersonalCloudPath })) {
                if (-not $dest.Path) { Write-Skip "$($dest.Label): no path supplied"; Add-Activity 'Exfiltrate' $dest.Label '-' 'Skipped'; continue }
                if (-not (Test-Path $dest.Path)) { Write-Warn "$($dest.Label): $($dest.Path) not found"; Add-Activity 'Exfiltrate' $dest.Label $dest.Path 'Failed'; continue }
                if ($PSCmdlet.ShouldProcess($dest.Path, "Copy $(Split-Path $source -Leaf)")) {
                    try {
                        Copy-Item -Path $source -Destination $dest.Path -Recurse -Force
                        Add-Activity 'Exfiltrate' $dest.Label $dest.Path 'Success'
                        Write-Ok "Copied to $($dest.Label) ($($dest.Path))"
                    }
                    catch {
                        Write-Fail "$($dest.Label): $($_.Exception.Message)"
                        Add-Activity 'Exfiltrate' $dest.Label $dest.Path 'Failed'
                    }
                }
            }
        }
    }
    #endregion

    #region Stage: Email
    if ('Email' -in $Stages) {
        Write-Step "Email - sending attachments to $ExternalRecipient"
        $files = @(Get-ChildItem -Path $downloadPath -File -ErrorAction SilentlyContinue | Select-Object -First 5)
        if ($files.Count -eq 0) {
            Write-Warn 'No downloaded files to attach. Run the Download stage first.'
            Add-Activity 'Email' 'SendMail' $ExternalRecipient 'Skipped'
        }
        elseif ($PSCmdlet.ShouldProcess($ExternalRecipient, "Send $($files.Count) attachments")) {
            $message = @{
                message = @{
                    subject      = "Files for my new role ($runId)"
                    body         = @{ contentType = 'Text'; content = 'Insider risk simulation - lab test data only.' }
                    toRecipients = @(@{ emailAddress = @{ address = $ExternalRecipient } })
                    attachments  = @($files | ForEach-Object {
                            @{
                                '@odata.type' = '#microsoft.graph.fileAttachment'
                                name          = $_.Name
                                contentType   = 'text/plain'
                                contentBytes  = [Convert]::ToBase64String([IO.File]::ReadAllBytes($_.FullName))
                            }
                        })
                }
                saveToSentItems = $true
            }
            try {
                Invoke-MgGraphRequest -Method POST -Uri 'v1.0/me/sendMail' -Body ($message | ConvertTo-Json -Depth 6) -ContentType 'application/json'
                Add-Activity 'Email' 'SendMail' $ExternalRecipient 'Success'
                Write-Ok "Sent $($files.Count) attachments"
            }
            catch {
                Write-Fail "Send failed: $($_.Exception.Message)"
                Add-Activity 'Email' 'SendMail' $ExternalRecipient 'Failed'
            }
        }
    }
    else {
        Write-Step 'Email - skipped (no -ExternalRecipient)'
    }
    #endregion

    #region Stage: Cleanup
    if ('Cleanup' -in $Stages) {
        Write-Step 'Cleanup - deleting local copies and recycling the SharePoint folder'
        if ($PSCmdlet.ShouldProcess($WorkingPath, 'Delete local simulation files')) {
            foreach ($path in @($downloadPath, $disguised, $archivePath)) {
                if (Test-Path $path) {
                    Remove-Item -Path $path -Recurse -Force
                    Add-Activity 'Cleanup' 'DeleteLocal' $path 'Success'
                }
            }
            Write-Ok 'Local copies deleted'
        }
        if ($PSCmdlet.ShouldProcess($SiteUrl, "Send /$folderName to the recycle bin")) {
            try {
                $folder = Invoke-MgGraphRequest -Method GET -Uri "v1.0/drives/$driveId/root:/$folderName"
                Invoke-MgGraphRequest -Method DELETE -Uri "v1.0/drives/$driveId/items/$($folder.id)"
                Add-Activity 'Cleanup' 'RecycleSharePointFolder' "/$folderName" 'Success'
                Write-Ok "/$folderName sent to the SharePoint recycle bin"
            }
            catch {
                Write-Skip "SharePoint folder not found or already removed"
                Add-Activity 'Cleanup' 'RecycleSharePointFolder' "/$folderName" 'Skipped'
            }
        }
        Write-Warn 'Copies on removable media, personal cloud folders and sent email are NOT removed. Delete them manually.'
    }
    #endregion
}
catch {
    Write-Fail $_.Exception.Message
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

#region Log and summary
if ($activity.Count -gt 0 -and -not $WhatIfPreference) {
    $logFile = Join-Path $LogPath "$runId-activity.csv"
    $activity | Export-Csv -Path $logFile -NoTypeInformation -Encoding UTF8
}

Write-Step 'Summary'
Write-Host ("   🆔 Run ID:     {0}" -f $runId)
Write-Host ("   ✅ Succeeded:  {0}" -f $summary.Succeeded)
Write-Host ("   ⏭️  Skipped:    {0}" -f $summary.Skipped)
Write-Host ("   ❌ Failed:     {0}" -f $summary.Failed)
if ($logFile) { Write-Host ("   📄 Activity log: {0}" -f $logFile) }
Write-Host "`n   ⏱️  Insider Risk Management alerts can take up to 24 hours to appear." -ForegroundColor Yellow
Write-Host '   🔎 Check Insider Risk Management > Alerts, filtered on the test user.' -ForegroundColor Yellow
#endregion
