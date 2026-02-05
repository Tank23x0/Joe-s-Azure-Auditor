[CmdletBinding()]
param(
    [string[]]$Sections,

    [ValidateSet('Csv', 'Html', 'Json')]
    [string]$OutputFormat = 'Html',

    [string]$OutputPath = (Get-Location).Path,

    [switch]$OpenHtmlReport,

    [switch]$SkipSharePointIfDisconnected,

    [string]$SharePointAdminUrl
)

if (-not $Sections) {
    $Sections = @('IdentityAccess', 'SharePoint', 'Logging')
}

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$invokePath = Join-Path $scriptPath 'Invoke-JoesAzureAuditor.ps1'

pwsh $invokePath -Scope Limited -Sections $Sections -OutputFormat $OutputFormat -OutputPath $OutputPath -OpenHtmlReport:$OpenHtmlReport -SkipSharePointIfDisconnected:$SkipSharePointIfDisconnected -SharePointAdminUrl $SharePointAdminUrl
