# Invoke-InsiderRiskSetup.ps1

Prepares a Microsoft 365 tenant for **Microsoft Purview Insider Risk Management** and verifies an Insider Risk policy created in the Purview portal.

Companion script for [Insider Risk Management Part 4: Creating your first policy](https://cloud-secure.ai/2026/10/31/insider-risk-management-part-4-creating-your-first-policy/), part of the cloud-secure.ai [Insider Risk Management series](https://cloud-secure.ai/2026/10/31/insider-risk-management-with-microsoft-purview-the-series/).

> To prove the policy works afterwards, use [Invoke-InsiderRiskSimulation](../Invoke-InsiderRiskSimulation) in a test environment.

## Why the script doesn't create the policy

Microsoft does not currently provide a documented, supported PowerShell cmdlet for creating Insider Risk policies. Security & Compliance PowerShell exposes `Get-InsiderRiskPolicy`, but it is undocumented, and Microsoft has previously advised against relying on the Insider Risk cmdlets.

Rather than depend on undocumented cmdlets, this script automates the **supported** parts of the setup and verifies the policy you create in the portal. The blog post walks through creating the policy step by step.

If your tenant exposes `New-InsiderRiskPolicy`, the script reports it but does not use it.

## What it does

| Step | Action | Changes the tenant? |
|---|---|---|
| 1 | Checks unified audit logging in Exchange Online | Only with `-EnableAuditing` |
| 2 | Adds users to the Insider Risk Management role groups | Yes (skips existing members) |
| 3 | Lists the Insider Risk cmdlets your tenant exposes | No |
| 4 | Verifies the named policy and exports it to JSON | No |

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- ExchangeOnlineManagement module 3.2 or later
  ```powershell
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  ```
- An account that is a **Global Administrator**, **Compliance Administrator** or member of **Organization Management**
- Microsoft 365 E5, or E3 with the E5 Compliance or E5 Insider Risk Management add-on

## Role groups

| Parameter | Role group | Purpose |
|---|---|---|
| `-AdminUpn` | Insider Risk Management Admins | Configure policies, settings and Adaptive Protection |
| `-AnalystUpn` | Insider Risk Management Analysts | Triage alerts and cases (pseudonymised) |
| `-InvestigatorUpn` | Insider Risk Management Investigators | Investigate cases, content and forensic evidence |
| `-AuditorUpn` | Insider Risk Management Auditors | View and export the Insider Risk audit log |
| `-ApproverUpn` | Insider Risk Management Approvers | Approve forensic evidence capture requests |

Global Administrators, Compliance Administrators and Organization Management members get Admins-level access only. They can create policies but **cannot view alerts or cases** until they are added to the Analysts, Investigators or Insider Risk Management role group.

Role group changes can take up to 30 minutes to apply.

### Recommended for production: compliance officers, PIM and groups

- Make **compliance officers**, not IT administrators, the members of the Analysts and Investigators role groups. IT has the widest access in the organisation, so IT staff should not be investigating themselves.
- For the role groups that can see alerts and reveal names, add a **PIM-enabled Microsoft Entra security group** in the Purview portal instead of individual users. Compliance officers are made eligible for the group and activate it just in time, with a time limit, justification and optional approval. Microsoft documents [PIM for Groups](https://learn.microsoft.com/en-us/purview/purview-permissions) as the way to get just-in-time access to Purview role groups.
- The `-*Upn` parameters add **individual users with standing access**. Use them for labs, pilots and the Admins role group, not for production alert access.

## Usage

Preview all changes first:

```powershell
.\Invoke-InsiderRiskSetup.ps1 `
    -AdminUpn admin@contoso.com `
    -AnalystUpn analyst1@contoso.com, analyst2@contoso.com `
    -InvestigatorUpn investigator@contoso.com `
    -EnableAuditing -WhatIf
```

Apply them:

```powershell
.\Invoke-InsiderRiskSetup.ps1 `
    -AdminUpn admin@contoso.com `
    -AnalystUpn analyst1@contoso.com, analyst2@contoso.com `
    -InvestigatorUpn investigator@contoso.com `
    -EnableAuditing
```

Verify and export a policy only:

```powershell
.\Invoke-InsiderRiskSetup.ps1 -PolicyName 'Contoso - Data theft by departing users' -SkipAuditCheck
```

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-AdminUpn`, `-AnalystUpn`, `-InvestigatorUpn`, `-AuditorUpn`, `-ApproverUpn` | none | Users to add to each role group |
| `-PolicyName` | `Contoso - Data theft by departing users` | Policy to verify and export |
| `-ExportPath` | Current folder | Where the JSON export is saved |
| `-EnableAuditing` | Off | Turns on unified audit logging if it is off |
| `-SkipAuditCheck` | Off | Skips the Exchange Online audit check |
| `-WhatIf` | Off | Shows changes without making them |

## Output

- Console output for each step, with a summary of members added, skipped and failed
- `<PolicyName>_<yyyyMMdd-HHmm>.json` - the policy configuration, for change records

## Notes

- No tenant IDs, object IDs or secrets are stored in the script. Everything tenant-specific is a parameter.
- The script signs in interactively. It does not store credentials.
- Turning on auditing is a tenant-wide change. Confirm with other administrators first.
- The Data theft by departing users template works best with the **HR connector**, which imports resignation dates. Without it, the policy falls back to Entra ID account deletion as the trigger. See the blog post for set-up steps.

## Author

Created by **Seán O'Farrell** - [cloud-secure.ai](https://cloud-secure.ai/)

Provided as is, without warranty. Test in a non-production tenant first.
