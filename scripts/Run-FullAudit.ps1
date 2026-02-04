[CmdletBinding()]
param(
    [ValidateSet('Csv', 'Html', 'Json')]
    [string]$OutputFormat = 'Html',

    [string]$OutputPath = (Get-Location).Path,

    [switch]$OpenHtmlReport
)

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$invokePath = Join-Path $scriptPath 'Invoke-JoesAzureAuditor.ps1'

pwsh $invokePath -Scope Full -OutputFormat $OutputFormat -OutputPath $OutputPath -OpenHtmlReport:$OpenHtmlReport
