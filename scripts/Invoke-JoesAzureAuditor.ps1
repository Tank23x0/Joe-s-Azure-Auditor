[CmdletBinding()]
param(
    [ValidateSet('Full', 'Limited')]
    [string]$Scope = 'Full',

    [string[]]$Sections = @(
        'IdentityAccess',
        'PrivilegedAccess',
        'M365SecurityBaseline',
        'SharePoint',
        'OneDrive',
        'DataProtection',
        'Logging',
        'DeviceIntegration',
        'AzureSubscription',
        'OAuthApps'
    ),

    [ValidateSet('Csv', 'Html', 'Json')]
    [string]$OutputFormat = 'Html',

    [string]$OutputPath = (Get-Location).Path,

    [switch]$OpenHtmlReport,

    [switch]$SkipSharePointIfDisconnected,

    [string]$SharePointAdminUrl
)

$ErrorActionPreference = 'Stop'

function Write-AuditorMessage {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $timestamp = (Get-Date).ToString('s')
    Write-Host ("[{0}] [{1}] {2}" -f $timestamp, $Level, $Message)
}

function Test-AndImportModule {
    param(
        [string]$Name
    )

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-AuditorMessage -Message ("Module {0} not found. Run Initialize-Environment.ps1 to install." -f $Name) -Level 'WARN'
        return $false
    }

    if (-not (Get-Module -Name $Name)) {
        Import-Module -Name $Name -ErrorAction Stop
    }

    if (-not (Get-Module -Name $Name)) {
        Write-AuditorMessage -Message ("Module {0} failed to load. Verify module installation." -f $Name) -Level 'ERROR'
        return $false
    }

    return $true
}

function Initialize-AuditorConnections {
    Write-AuditorMessage -Message 'Initializing module imports and tenant connections.'

    $moduleChecks = @(
        'Az.Accounts',
        'Az.Resources',
        'Az.Security',
        'Az.Monitor',
        'Microsoft.Graph',
        'ExchangeOnlineManagement',
        'Microsoft.Online.SharePoint.PowerShell',
        'PnP.PowerShell'
    )

    $loadedModules = @()
    foreach ($moduleName in $moduleChecks) {
        if (Test-AndImportModule -Name $moduleName) {
            $loadedModules += $moduleName
        }
    }

    if ($loadedModules -contains 'Az.Accounts') {
        if (-not (Get-AzContext)) {
            Connect-AzAccount -ErrorAction Stop | Out-Null
        }
    }

    if ($loadedModules -contains 'Microsoft.Graph') {
        $graphScopes = @(
            'Directory.Read.All',
            'Policy.Read.All',
            'SecurityEvents.Read.All',
            'IdentityRiskyUser.Read.All',
            'IdentityRiskySignIn.Read.All',
            'AuditLog.Read.All',
            'Organization.Read.All',
            'User.Read.All',
            'Group.Read.All'
        )
        Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop | Out-Null
        Select-MgProfile -Name 'v1.0'
    }

    if ($loadedModules -contains 'ExchangeOnlineManagement') {
        $exchangeConnected = $false
        if (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            $exchangeConnected = [bool](Get-ConnectionInformation)
        }
        if (-not $exchangeConnected) {
            Connect-ExchangeOnline -ShowBanner:$false
        } else {
            Write-AuditorMessage -Message 'Exchange Online session already active; reusing existing connection.' -Level 'INFO'
        }
    }

    if ($loadedModules -contains 'Microsoft.Online.SharePoint.PowerShell') {
        $sharepointConnected = Test-SPOConnection
        if ($sharepointConnected) {
            Write-AuditorMessage -Message 'SharePoint Online session already active; reusing existing connection.' -Level 'INFO'
        } else {
            if ($SkipSharePointIfDisconnected) {
                Write-AuditorMessage -Message 'SharePoint Online is disconnected; skipping SharePoint/OneDrive sections.' -Level 'WARN'
            } else {
                if (-not $SharePointAdminUrl) {
                    $SharePointAdminUrl = Read-Host 'Enter SharePoint admin URL (https://<tenant>-admin.sharepoint.com)'
                }
                if ($SharePointAdminUrl) {
                    Connect-SPOService -Url $SharePointAdminUrl
                    if (-not (Test-SPOConnection)) {
                        Write-AuditorMessage -Message 'SharePoint connection failed; SharePoint/OneDrive sections will be skipped.' -Level 'WARN'
                    }
                } else {
                    Write-AuditorMessage -Message 'SharePoint admin URL not provided; SharePoint/OneDrive sections will be skipped.' -Level 'WARN'
                }
            }
        }
    }

    if ($loadedModules -contains 'PnP.PowerShell') {
        Write-AuditorMessage -Message 'Connect-PnPOnline required for deeper SharePoint insights (PnP). Use with -Interactive.' -Level 'WARN'
    }
}

function Test-SPOConnection {
    try {
        Get-SPOTenant -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function New-Section {
    param(
        [string]$Name,
        [string]$RiskSummary
    )

    return [ordered]@{
        Name = $Name
        RiskSummary = $RiskSummary
        Findings = @()
        Evidence = @()
    }
}

function Add-Finding {
    param(
        [hashtable]$Section,
        [string]$Title,
        [string]$Severity,
        [string]$Details
    )

    $Section.Findings += [ordered]@{
        Title = $Title
        Severity = $Severity
        Details = $Details
    }
}

function Add-Evidence {
    param(
        [hashtable]$Section,
        [string]$Name,
        [object]$Data
    )

    $Section.Evidence += [ordered]@{
        Name = $Name
        Data = $Data
    }
}

function Get-IdentityAccessSection {
    $section = New-Section -Name 'Identity & Access Management' -RiskSummary 'High'

    $globalAdmins = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq 'Global Administrator' }
    Add-Evidence -Section $section -Name 'DirectoryRoles' -Data $globalAdmins

    $roleAssignments = Get-MgDirectoryRole | ForEach-Object {
        Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id
    }
    Add-Evidence -Section $section -Name 'PrivilegedRoleAssignments' -Data $roleAssignments

    $conditionalAccess = Get-MgConditionalAccessPolicy
    Add-Evidence -Section $section -Name 'ConditionalAccessPolicies' -Data $conditionalAccess

    $riskyUsers = Get-MgIdentityProtectionRiskyUser
    Add-Evidence -Section $section -Name 'RiskyUsers' -Data $riskyUsers

    $riskySignIns = Get-MgIdentityProtectionRiskySignIn
    Add-Evidence -Section $section -Name 'RiskySignIns' -Data $riskySignIns

    Add-Finding -Section $section -Title 'Review Global Administrator count' -Severity 'High' -Details 'Confirm GA count remains minimal and break-glass accounts are excluded but monitored.'
    Add-Finding -Section $section -Title 'Conditional Access coverage' -Severity 'High' -Details 'Validate MFA, legacy auth blocking, and geo/device/risk policies are enforced.'

    return $section
}

function Get-PrivilegedAccessSection {
    $section = New-Section -Name 'Privileged Access & Governance' -RiskSummary 'High'

    $pimRoles = Get-MgIdentityGovernancePrivilegedAccessRoleAssignment -ProviderId 'aadRoles'
    Add-Evidence -Section $section -Name 'PIMRoleAssignments' -Data $pimRoles

    $accessReviews = Get-MgIdentityGovernanceAccessReviewDefinition
    Add-Evidence -Section $section -Name 'AccessReviewDefinitions' -Data $accessReviews

    Add-Finding -Section $section -Title 'PIM coverage' -Severity 'High' -Details 'Ensure admin roles are eligible-only with approval and JIT activation.'
    Add-Finding -Section $section -Title 'Access reviews' -Severity 'Medium' -Details 'Confirm regular reviews for admins, guests, and SharePoint owners.'

    return $section
}

function Get-M365SecurityBaselineSection {
    $section = New-Section -Name 'Microsoft 365 Security Baseline' -RiskSummary 'Medium'

    $secureScore = Get-MgSecuritySecureScore
    Add-Evidence -Section $section -Name 'SecureScore' -Data $secureScore

    $antiPhish = Get-AntiPhishPolicy
    $safeLinks = Get-SafeLinksPolicy
    $safeAttachments = Get-SafeAttachmentPolicy
    $contentFilter = Get-HostedContentFilterPolicy
    Add-Evidence -Section $section -Name 'AntiPhishPolicies' -Data $antiPhish
    Add-Evidence -Section $section -Name 'SafeLinksPolicies' -Data $safeLinks
    Add-Evidence -Section $section -Name 'SafeAttachmentPolicies' -Data $safeAttachments
    Add-Evidence -Section $section -Name 'HostedContentFilterPolicies' -Data $contentFilter

    Add-Finding -Section $section -Title 'Secure Score gaps' -Severity 'Medium' -Details 'Prioritize MFA, Conditional Access, and admin protection actions.'
    Add-Finding -Section $section -Title 'Defender for O365 tuning' -Severity 'Medium' -Details 'Validate Safe Links, Safe Attachments, and anti-phishing coverage.'

    return $section
}

function Get-SharePointSection {
    $section = New-Section -Name 'SharePoint Online Security' -RiskSummary 'High'

    $tenantSettings = Get-SPOTenant
    Add-Evidence -Section $section -Name 'SPOTenantSettings' -Data $tenantSettings

    $sites = Get-SPOSite -Limit All
    Add-Evidence -Section $section -Name 'SPOSiteInventory' -Data $sites

    Add-Finding -Section $section -Title 'External sharing posture' -Severity 'High' -Details 'Review tenant and site-level anonymous sharing, default link type, and site owners.'

    return $section
}

function Get-OneDriveSection {
    $section = New-Section -Name 'OneDrive for Business Security' -RiskSummary 'High'

    $oneDriveSettings = Get-SPOTenant
    Add-Evidence -Section $section -Name 'OneDriveTenantSettings' -Data $oneDriveSettings

    Add-Finding -Section $section -Title 'OneDrive lifecycle controls' -Severity 'High' -Details 'Confirm retention, dormant accounts, and ex-employee access handling.'

    return $section
}

function Get-DataProtectionSection {
    $section = New-Section -Name 'Data Protection & Compliance' -RiskSummary 'High'

    $labels = Get-ComplianceTag
    Add-Evidence -Section $section -Name 'SensitivityLabels' -Data $labels

    $retentionPolicies = Get-RetentionCompliancePolicy
    Add-Evidence -Section $section -Name 'RetentionPolicies' -Data $retentionPolicies

    $dlpPolicies = Get-DlpCompliancePolicy
    Add-Evidence -Section $section -Name 'DlpPolicies' -Data $dlpPolicies

    Add-Finding -Section $section -Title 'DLP & classification' -Severity 'High' -Details 'Confirm sensitivity labels, encryption, and DLP coverage for SharePoint/OneDrive/Teams.'

    return $section
}

function Get-LoggingSection {
    $section = New-Section -Name 'Logging, Monitoring & Incident Readiness' -RiskSummary 'High'

    $auditConfig = Get-AdminAuditLogConfig
    Add-Evidence -Section $section -Name 'UnifiedAuditLogConfig' -Data $auditConfig

    $signInLogs = Get-MgAuditLogSignIn -Top 25
    Add-Evidence -Section $section -Name 'SignInLogsSample' -Data $signInLogs

    Add-Finding -Section $section -Title 'Audit log retention' -Severity 'High' -Details 'Verify UAL is enabled and retention meets investigation needs.'

    return $section
}

function Get-DeviceIntegrationSection {
    $section = New-Section -Name 'Device & Endpoint Integration' -RiskSummary 'Medium'

    $deviceCompliance = Get-MgDeviceManagementDeviceCompliancePolicy
    Add-Evidence -Section $section -Name 'DeviceCompliancePolicies' -Data $deviceCompliance

    Add-Finding -Section $section -Title 'Conditional Access device controls' -Severity 'Medium' -Details 'Validate compliance requirements and app protection for BYOD.'

    return $section
}

function Get-AzureSubscriptionSection {
    $section = New-Section -Name 'Azure Subscription Security' -RiskSummary 'Medium'

    $subscriptions = Get-AzSubscription
    Add-Evidence -Section $section -Name 'Subscriptions' -Data $subscriptions

    $resourceGroups = Get-AzResourceGroup
    Add-Evidence -Section $section -Name 'ResourceGroups' -Data $resourceGroups

    $resources = Get-AzResource
    Add-Evidence -Section $section -Name 'Resources' -Data $resources

    $roleAssignments = Get-AzRoleAssignment
    Add-Evidence -Section $section -Name 'AzureRBACAssignments' -Data $roleAssignments

    $roleDefinitions = Get-AzRoleDefinition
    Add-Evidence -Section $section -Name 'AzureRBACRoleDefinitions' -Data $roleDefinitions

    $policyAssignments = Get-AzPolicyAssignment
    Add-Evidence -Section $section -Name 'PolicyAssignments' -Data $policyAssignments

    $policyDefinitions = Get-AzPolicyDefinition
    Add-Evidence -Section $section -Name 'PolicyDefinitions' -Data $policyDefinitions

    $policySetDefinitions = Get-AzPolicySetDefinition
    Add-Evidence -Section $section -Name 'PolicySetDefinitions' -Data $policySetDefinitions

    $servicePrincipals = Get-AzADServicePrincipal
    Add-Evidence -Section $section -Name 'ServicePrincipals' -Data $servicePrincipals

    $defenderPlans = Get-AzSecurityPricing
    Add-Evidence -Section $section -Name 'DefenderForCloudPlans' -Data $defenderPlans

    $securityContacts = Get-AzSecurityContact
    Add-Evidence -Section $section -Name 'DefenderSecurityContacts' -Data $securityContacts

    $autoProvision = Get-AzSecurityAutoProvisioningSetting
    Add-Evidence -Section $section -Name 'DefenderAutoProvisioning' -Data $autoProvision

    Add-Finding -Section $section -Title 'RBAC sprawl' -Severity 'Medium' -Details 'Review high-privilege role assignments and stale service principals.'

    return $section
}

function Get-OAuthAppsSection {
    $section = New-Section -Name 'Third-Party App & OAuth Risk' -RiskSummary 'High'

    $servicePrincipals = Get-MgServicePrincipal
    Add-Evidence -Section $section -Name 'OAuthServicePrincipals' -Data $servicePrincipals

    Add-Finding -Section $section -Title 'OAuth app governance' -Severity 'High' -Details 'Review consented apps for over-privileged scopes and stale usage.'

    return $section
}

function Export-AuditReport {
    param(
        [hashtable]$Report,
        [string]$Format,
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }

    switch ($Format) {
        'Json' {
            $jsonPath = Join-Path $Path 'JoesAzureAuditor-Report.json'
            $Report | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding utf8
            return $jsonPath
        }
        'Csv' {
            $csvPath = Join-Path $Path 'JoesAzureAuditor-Findings.csv'
            $flatFindings = foreach ($section in $Report.Sections) {
                foreach ($finding in $section.Findings) {
                    [pscustomobject]@{
                        Section = $section.Name
                        RiskSummary = $section.RiskSummary
                        Title = $finding.Title
                        Severity = $finding.Severity
                        Details = $finding.Details
                    }
                }
            }
            $flatFindings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
            return $csvPath
        }
        'Html' {
            $htmlPath = Join-Path $Path 'JoesAzureAuditor-Report.html'
            $sectionBlocks = foreach ($section in $Report.Sections) {
                $findingsTable = $section.Findings | ConvertTo-Html -Fragment -PreContent "<h4>Findings</h4>"
                $evidenceTable = $section.Evidence | ConvertTo-Html -Fragment -PreContent "<h4>Evidence</h4>"
                "<section><h2>$($section.Name)</h2><p><strong>Risk Summary:</strong> $($section.RiskSummary)</p>$findingsTable$evidenceTable</section>"
            }

            $html = @"
<!DOCTYPE html>
<html>
<head>
<title>Joe's Azure Auditor Report</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; }
section { margin-bottom: 32px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; }
th { background-color: #f3f3f3; }
</style>
</head>
<body>
<h1>Joe's Azure Auditor Report</h1>
<p><strong>Tenant:</strong> $($Report.Metadata.Tenant)</p>
<p><strong>Generated:</strong> $($Report.Metadata.GeneratedAt)</p>
$($sectionBlocks -join "\n")
</body>
</html>
"@
            $html | Out-File -FilePath $htmlPath -Encoding utf8
            return $htmlPath
        }
    }
}

Write-AuditorMessage -Message ("Starting audit in {0} mode." -f $Scope)
Initialize-AuditorConnections

$report = [ordered]@{
    Metadata = [ordered]@{
        Tenant = (Get-MgOrganization | Select-Object -First 1).DisplayName
        GeneratedAt = (Get-Date).ToString('u')
        Scope = $Scope
        Sections = $Sections
        ManualScriptsReference = 'docs/Manual-Scripts-Index.md'
        FrameworkMappingReference = 'docs/Framework-Mapping.md'
    }
    Sections = @()
}

$requestedSections = if ($Scope -eq 'Full') {
    $Sections
} else {
    $Sections
}

foreach ($sectionName in $requestedSections) {
    switch ($sectionName) {
        'IdentityAccess' { $report.Sections += Get-IdentityAccessSection }
        'PrivilegedAccess' { $report.Sections += Get-PrivilegedAccessSection }
        'M365SecurityBaseline' { $report.Sections += Get-M365SecurityBaselineSection }
        'SharePoint' {
            if (Test-SPOConnection) {
                $report.Sections += Get-SharePointSection
            } else {
                Write-AuditorMessage -Message 'Skipping SharePoint section due to missing SPO connection.' -Level 'WARN'
            }
        }
        'OneDrive' {
            if (Test-SPOConnection) {
                $report.Sections += Get-OneDriveSection
            } else {
                Write-AuditorMessage -Message 'Skipping OneDrive section due to missing SPO connection.' -Level 'WARN'
            }
        }
        'DataProtection' { $report.Sections += Get-DataProtectionSection }
        'Logging' { $report.Sections += Get-LoggingSection }
        'DeviceIntegration' { $report.Sections += Get-DeviceIntegrationSection }
        'AzureSubscription' { $report.Sections += Get-AzureSubscriptionSection }
        'OAuthApps' { $report.Sections += Get-OAuthAppsSection }
        default { Write-AuditorMessage -Message ("Unknown section requested: {0}" -f $sectionName) -Level 'WARN' }
    }
}

$outputFile = Export-AuditReport -Report $report -Format $OutputFormat -Path $OutputPath
Write-AuditorMessage -Message ("Report exported to {0}" -f $outputFile)

if ($OpenHtmlReport -and $OutputFormat -eq 'Html') {
    Start-Process $outputFile
}

Write-AuditorMessage -Message 'If you need to reset sessions, consider Disconnect-MgGraph, Disconnect-ExchangeOnline, and Disconnect-SPOService.' -Level 'INFO'
