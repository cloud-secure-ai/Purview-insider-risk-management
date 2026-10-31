# Insider Risk Management - KQL hunting queries

Advanced hunting queries for **Microsoft Defender XDR** that show insider risk activity, especially people taking data before they leave.

Companion to [Insider Risk Management Part 4: Creating your first policy](https://cloud-secure.ai/2026/10/31/insider-risk-management-part-4-creating-your-first-policy/), part of the cloud-secure.ai [Insider Risk Management series](https://cloud-secure.ai/2026/10/31/insider-risk-management-with-microsoft-purview-the-series/).

## What is KQL?

KQL (Kusto Query Language) is the language used to search security data in Microsoft Defender and Microsoft Sentinel. You paste a query into **Microsoft Defender portal > Investigation & response > Hunting > Advanced hunting**, select **Run query**, and get a table of results.

## The queries

All queries are in [insider-risk-hunting.kql](insider-risk-hunting.kql). Copy one query at a time into advanced hunting.

| # | Query | Needs Insider Risk data in Defender? | What it shows |
|---|---|---|---|
| 1 | Discover alert sources | No | The exact `ServiceSource` names in your tenant - run this first |
| 2 | Insider Risk alerts by person | Yes | Insider Risk alerts with the people involved and the highest severity |
| 3 | Copies to removable media | Yes | Files copied to USB, with the device make, model and serial number |
| 4 | Sensitivity label changes | Yes | Files whose sensitivity label was removed or changed |
| 5 | Leaver activity timeline | **No** | SharePoint and OneDrive downloads, archives created and external email with attachments, for the leavers you list |
| 6 | Leaver download summary | **No** | One row per leaver, ranked by downloads |
| 7 | Find a simulation run | **No** | Everything [Invoke-InsiderRiskSimulation](../Invoke-InsiderRiskSimulation) did, in time order |

Queries 5 and 6 work in any tenant with Defender, **even without Insider Risk Management**. Run them against recent leavers to show what you have been missing.

## Before you run them

**For queries 2 to 4 (Insider Risk data):**

1. In the Purview portal, go to **Insider Risk Management > Settings > Data sharing** and turn on **Sharing data with other Microsoft security solutions**.
2. Make sure you are in the **Insider Risk Management Analysts** or **Insider Risk Management Investigators** role group. Admin roles alone are not enough.
3. `DataSecurityEvents` is a preview table and can change.

**For queries 5 and 6:** replace the example addresses and dates in the `datatable` at the top with your own leavers.

**For query 2:** if it returns nothing, run query 1 and replace `"Insider Risk"` with the `ServiceSource` value shown for Insider Risk Management in your tenant.

## Tables used

| Table | Source |
|---|---|
| `AlertInfo`, `AlertEvidence` | Alerts from all Defender and Purview sources, including Insider Risk Management |
| `DataSecurityEvents` (preview) | Insider Risk Management activity, shared from Purview |
| `CloudAppEvents` | Microsoft 365 activity, such as SharePoint and OneDrive downloads |
| `DeviceFileEvents` | File activity on devices onboarded to Defender for Endpoint |
| `EmailEvents` | Email processed by Exchange Online Protection and Defender for Office 365 |

## References

- [DataSecurityEvents table - Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-datasecurityevents-table)
- [Investigate insider risk threats in the Microsoft Defender portal - Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/irm-investigate-alerts-defender)
- [Share Insider Risk Management data with other solutions - Microsoft Learn](https://learn.microsoft.com/en-us/purview/insider-risk-management-settings-share-data)

## Author

Created by **Seán O'Farrell** - [cloud-secure.ai](https://cloud-secure.ai/)

Provided as is, without warranty. Test in a non-production tenant first.
