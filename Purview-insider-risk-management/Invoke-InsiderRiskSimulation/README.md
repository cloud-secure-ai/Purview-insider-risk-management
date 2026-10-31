# Invoke-InsiderRiskSimulation.ps1

> ⚠️ **LAB TENANTS AND TEST USERS ONLY.** This script deliberately behaves like a departing employee stealing data. Never run it in production.

Simulates a departing user exfiltrating data, so you can prove an Insider Risk policy works and capture the resulting alert.

Companion script for [Insider Risk Management Part 4: Creating your first policy](https://cloud-secure.ai/insider-risk-management-part-4/). Set up the roles and policy first with [Invoke-InsiderRiskSetup](../Invoke-InsiderRiskSetup).

## How it works

The script runs in stages that mirror the sequences Insider Risk Management detects - download, obfuscate, exfiltrate, delete:

| Stage | What it does | Signals it generates |
|---|---|---|
| `Seed` | Creates test files with dummy card numbers and IBANs, uploads them to a SharePoint site | File uploads containing sensitive information types |
| `Download` | Downloads the files to the device | Downloading content from SharePoint |
| `Obfuscate` | Compresses the files and renames the archive to `holiday-photos-<date>.dat` | Archive creation, file renamed to a misleading extension |
| `Exfiltrate` | Copies the archive to USB and/or a personal cloud sync folder | Copy to removable media, copy to personal cloud storage |
| `Email` | Emails up to five files to an external address (only with `-ExternalRecipient`) | Email with attachments outside the organisation |
| `Cleanup` | Deletes local copies and sends the SharePoint folder to the recycle bin | Deleting files - completing the sequence |

Every action is logged with a UTC timestamp to `IRMSIM-<timestamp>-activity.csv`, so you can match it against the alert timeline.

The test data uses published test values (such as `4111 1111 1111 1111`) and every file is marked as simulation test data, but it still matches sensitive information types. That is deliberate - it raises the risk score.

## Before you run it

1. **Use a lab tenant and a dedicated test account.** The script checks that the signed-in tenant owns `-LabTenantDomain` and stops if it does not.
2. **Run it as the test user, on a Windows device onboarded to Defender for Endpoint.** Device indicators (USB, personal cloud, archive, rename) are attributed to the user signed in to Windows.
3. **Bring the test user into scope**, either:
   - **Start scoring activity for users** on the Insider Risk Management Policies page (quickest), or
   - upload a resignation record for the test user through the **HR connector** (most realistic).
4. **Install the Graph authentication module:**
   ```powershell
   Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
   ```
   The script signs in interactively with delegated permissions: `Sites.ReadWrite.All`, `Files.ReadWrite.All`, and `Mail.Send` for the Email stage.

## Usage

Preview everything first:

```powershell
.\Invoke-InsiderRiskSimulation.ps1 `
    -LabTenantDomain contosolab.onmicrosoft.com -IUnderstandThisIsALab `
    -SiteUrl https://contosolab.sharepoint.com/sites/Projects `
    -RemovableMediaPath E:\ -WhatIf
```

Run the full simulation:

```powershell
.\Invoke-InsiderRiskSimulation.ps1 `
    -LabTenantDomain contosolab.onmicrosoft.com -IUnderstandThisIsALab `
    -SiteUrl https://contosolab.sharepoint.com/sites/Projects `
    -RemovableMediaPath E:\ `
    -PersonalCloudPath "$env:USERPROFILE\Dropbox" `
    -ExternalRecipient my.personal.address@outlook.com
```

Seed as an admin, then run the rest as the test user later:

```powershell
# As admin
.\Invoke-InsiderRiskSimulation.ps1 -LabTenantDomain contosolab.onmicrosoft.com -IUnderstandThisIsALab `
    -SiteUrl https://contosolab.sharepoint.com/sites/Projects -Stages Seed
```

Then, signed in as the test user, run the remaining stages against the same folder (the Seed run prints its folder name):

```powershell
# As the test user
.\Invoke-InsiderRiskSimulation.ps1 -LabTenantDomain contosolab.onmicrosoft.com -IUnderstandThisIsALab `
    -SiteUrl https://contosolab.sharepoint.com/sites/Projects -FolderName IRMSIM-20261031-210000 `
    -Stages Download, Obfuscate, Exfiltrate, Cleanup -RemovableMediaPath E:\
```

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-LabTenantDomain` | required | A verified domain of the lab tenant - used as a safety check |
| `-IUnderstandThisIsALab` | required | Confirms this is a lab tenant with a test account |
| `-SiteUrl` | required | SharePoint site for the test files |
| `-FileCount` | `40` | Number of test files (5-500) |
| `-RemovableMediaPath` | none | USB path, for example `E:\` |
| `-PersonalCloudPath` | none | Personal cloud sync folder |
| `-ExternalRecipient` | none | External email address. Email stage is skipped without it |
| `-Stages` | all | Any of `Seed`, `Download`, `Obfuscate`, `Exfiltrate`, `Email`, `Cleanup` |
| `-WorkingPath` | `%TEMP%\IRM-Simulation` | Local working folder |
| `-FolderName` | new `IRMSIM-<timestamp>` | Reuse the folder from an earlier Seed run |
| `-LogPath` | current folder | Where the activity CSV is written |
| `-WhatIf` | off | Shows actions without performing them |

## After the run

- Alerts can take **up to 24 hours** to appear in **Insider Risk Management > Alerts**.
- Copies on USB, in personal cloud folders and in sent email are **not** removed by `Cleanup`. Delete them yourself.
- The SharePoint folder goes to the **recycle bin**, not permanent deletion.
- To also test the **label downgrade** indicator, manually remove or downgrade a sensitivity label on one of the files before the Download stage.

## Author

Created by **Seán O'Farrell** - [cloud-secure.ai](https://cloud-secure.ai/)

Provided as is, without warranty. Test in a non-production tenant first.
