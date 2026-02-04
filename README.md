# Joe's Azure Auditor

A PowerShell-based auditing toolkit for Microsoft Azure and Microsoft 365 tenants. It provides **Full** and **Limited** audit modes and produces **CSV**, **HTML**, or **JSON** outputs for a 30,000‑ft security review. The structure is intentionally split into **setup** and **action** scripts for rapid use.

## What this does (30,000‑ft review)
- Identity & Access Management (Entra ID)
- Privileged Access & Governance (PIM, access reviews)
- Microsoft 365 Security Baseline (Secure Score, Defender for O365)
- SharePoint Online & OneDrive Security
- Data Protection & Compliance (DLP, labels, retention)
- Logging & Incident Readiness
- Device & Endpoint Integration (Intune/CA)
- Azure Subscription Security (RBAC, apps, Defender for Cloud)
- Third‑Party OAuth App Risk

## Repository Layout
```
./scripts
  Initialize-Environment.ps1   # setup + module checks
  Run-FullAudit.ps1            # wrapper for full audit
  Run-LimitedAudit.ps1         # wrapper for limited audit
  Invoke-JoesAzureAuditor.ps1  # main auditing script
./docs
  Manual-Scripts-Index.md      # manual scripts catalog (alphabetical)
  Framework-Mapping.md         # CIS / NIST / ISO 27001 mapping with URLs
  Audit-Approach.md            # 30,000-ft review mindset + red flags
./templates
  Report-Executive-Summary.md  # leadership summary template
```

## Prerequisites
- PowerShell 7+
- Microsoft 365 Global Reader or Security Reader (minimum)
- Exchange/SharePoint admin permissions where required
- Azure AD/Entra permissions for Graph access

## Quick Start

### 1) Setup / module checks
```powershell
pwsh ./scripts/Initialize-Environment.ps1
```

### 2) Full audit (all sections)
```powershell
pwsh ./scripts/Run-FullAudit.ps1 -OutputFormat Html -OutputPath ./reports
```

### 3) Limited audit (choose sections)
```powershell
pwsh ./scripts/Run-LimitedAudit.ps1 -Sections IdentityAccess,SharePoint,Logging -OutputFormat Csv -OutputPath ./reports
```

### 4) HTML report preview
The HTML report is placed in the output directory and can be opened directly:
```powershell
Start-Process ./reports/JoesAzureAuditor-Report.html
```

## Output options
- **CSV**: structured findings and evidence tables for spreadsheet review
- **HTML**: leadership‑friendly report with sections and quick findings
- **JSON**: raw structured output for integrations
- **Current directory** is the default output path (use `-OutputPath` to override)

## Manual evidence collection
See `docs/Manual-Scripts-Index.md` for a **dictionary‑ordered** list of manual commands and evidence queries, including Graph and PowerShell one‑liners.

## Audit approach
See `docs/Audit-Approach.md` for the 30,000‑ft review mindset, red‑flag signals, and executive‑level framing.

## Framework mappings
See `docs/Framework-Mapping.md` for CIS, NIST, and ISO 27001 mappings with URL sources per section.

## Notes
- Full audit mode collects the widest possible set of tenant data from **Az**, **Microsoft.Graph**, **ExchangeOnlineManagement**, **SharePoint Online**, **PnP.PowerShell**, and **Microsoft 365 Defender** where available.
- Limited audit mode includes only the selected sections.
- If a module is missing, the setup script will offer install guidance and log a warning.
