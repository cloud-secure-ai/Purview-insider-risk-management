# Purview-insider-risk-management

PowerShell scripts and KQL hunting queries that accompany the cloud-secure.ai blog series **[Insider Risk Management with Microsoft Purview](https://cloud-secure.ai/insider-risk-management-series-guide/)**.

| Folder | What it does | Where to run it |
|---|---|---|
| [Invoke-InsiderRiskSetup](Invoke-InsiderRiskSetup) | Checks audit logging, assigns the Insider Risk Management role groups, and verifies and exports your insider risk policy | Any tenant (supports `-WhatIf`) |
| [Invoke-InsiderRiskSimulation](Invoke-InsiderRiskSimulation) | Simulates a departing user taking data - download, disguise, copy out, email, delete - so you can prove the policy raises an alert | **Lab tenants and test users only** |
| [Hunting-Queries](Hunting-Queries) | Seven KQL queries for Defender advanced hunting: Insider Risk alerts, USB copies, label changes, a leaver activity timeline (works without Insider Risk Management) and a simulation finder | Microsoft Defender portal |

## Why there is no script to create the policy

Microsoft does not provide a documented, supported PowerShell cmdlet for creating Insider Risk policies. Create the policy in the Microsoft Purview portal - [Part 4](https://cloud-secure.ai/insider-risk-management-part-4/) walks through every step with screenshots - then use these scripts to set up the roles around it and prove it works.

## Typical order

1. Run **Invoke-InsiderRiskSetup.ps1** with `-WhatIf`, then without, to check auditing and assign roles.
2. Create the **Data theft by departing users** policy in the Purview portal.
3. Run **Invoke-InsiderRiskSetup.ps1** again to verify and export the policy.
4. In a lab tenant, bring a test user into scope and run **Invoke-InsiderRiskSimulation.ps1** as that user.
5. Check **Insider Risk Management > Alerts** within 24 hours.
6. Run the **Hunting-Queries** in Defender advanced hunting to see the same activity and the alert side by side.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- `ExchangeOnlineManagement` 3.2 or later (setup script)
- `Microsoft.Graph.Authentication` (simulation script)
- Microsoft 365 E5, or E3 with the E5 Compliance or E5 Insider Risk Management add-on

Neither script stores tenant IDs, object IDs or credentials. Both sign in interactively.

## Author

Created by **Seán O'Farrell** - [cloud-secure.ai](https://cloud-secure.ai/)

Provided as is, without warranty. Test in a non-production tenant first.
