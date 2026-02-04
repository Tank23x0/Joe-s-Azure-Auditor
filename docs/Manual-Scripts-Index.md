# Manual Scripts Index (Alphabetical)

Use this catalog for manual evidence gathering when automation is blocked. All sections are listed in **dictionary order** and include PowerShell or Graph examples.

## Access Reviews
```powershell
Get-MgIdentityGovernanceAccessReviewDefinition | Select-Object DisplayName, Status, CreatedDateTime
```

## Admin Roles
```powershell
Get-MgDirectoryRole | Select-Object DisplayName, Id
Get-MgDirectoryRole | ForEach-Object { Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id }
```

## App Consents (OAuth)
```powershell
Get-MgServicePrincipal | Where-Object { $_.AppOwnerOrganizationId } | Select-Object DisplayName, AppId, AccountEnabled
```

## Audit Log (Unified)
```powershell
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled, AdminAuditLogEnabled
```

## Azure RBAC Assignments
```powershell
Get-AzRoleAssignment | Select-Object PrincipalName, RoleDefinitionName, Scope
```

## Conditional Access Policies
```powershell
Get-MgConditionalAccessPolicy | Select-Object DisplayName, State, CreatedDateTime
```

## DLP Policies
```powershell
Get-DlpCompliancePolicy | Select-Object Name, Mode, State
```

## Defender for Cloud Plans
```powershell
Get-AzSecurityPricing | Select-Object Name, PricingTier
```

## Exchange Anti-Phish / Safe Links
```powershell
Get-AntiPhishPolicy
Get-SafeLinksPolicy
Get-SafeAttachmentPolicy
```

## External Sharing (SharePoint)
```powershell
Get-SPOTenant | Select-Object SharingCapability, DefaultSharingLinkType, DefaultLinkPermission
Get-SPOSite -Limit All | Select-Object Title, Url, SharingCapability
```

## Guest Users
```powershell
Get-MgUser -Filter "userType eq 'Guest'" | Select-Object DisplayName, UserPrincipalName, CreatedDateTime
```

## Identity Protection - Risky Users
```powershell
Get-MgIdentityProtectionRiskyUser | Select-Object UserDisplayName, RiskLevel, RiskState
```

## Identity Protection - Risky Sign-ins
```powershell
Get-MgIdentityProtectionRiskySignIn | Select-Object UserDisplayName, RiskLevel, RiskState, ActivityDateTime
```

## MFA Methods (User Registration)
```powershell
Get-MgReportAuthenticationMethodUserRegistrationDetail
```

## OneDrive Retention
```powershell
Get-SPOTenant | Select-Object OrphanedPersonalSitesRetentionPeriod
```

## PIM Role Assignments
```powershell
Get-MgIdentityGovernancePrivilegedAccessRoleAssignment -ProviderId 'aadRoles'
```

## Retention Policies
```powershell
Get-RetentionCompliancePolicy | Select-Object Name, Enabled, Mode
```

## Secure Score
```powershell
Get-MgSecuritySecureScore | Select-Object CurrentScore, MaxScore, CreatedDateTime
```

## Service Principals (Azure AD Apps)
```powershell
Get-AzADServicePrincipal | Select-Object DisplayName, AppId, AccountEnabled
```

## SharePoint Site Owners
```powershell
Get-SPOSite -Limit All | Select-Object Title, Url, Owner
```

## Teams DLP Coverage
```powershell
Get-DlpComplianceRule | Where-Object { $_.ContentContainsSensitiveInformation } | Select-Object Name, Policy, Mode
```
