[CmdletBinding()]
param(
    [switch]$InstallMissingModules
)

$ErrorActionPreference = 'Stop'

function Write-ModuleStatus {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Details
    )
    Write-Host ("[{0}] {1} - {2}" -f $Status, $Name, $Details)
}

function Test-ModulePresence {
    param(
        [string]$Name,
        [string]$MinimumVersion = $null
    )

    $module = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $module) {
        Write-ModuleStatus -Name $Name -Status 'MISSING' -Details 'Module not found in PSModulePath.'
        return $false
    }

    if ($MinimumVersion -and ([version]$module.Version -lt [version]$MinimumVersion)) {
        Write-ModuleStatus -Name $Name -Status 'OUTDATED' -Details ("Found {0}, requires {1}." -f $module.Version, $MinimumVersion)
        return $false
    }

    Write-ModuleStatus -Name $Name -Status 'OK' -Details ("Found {0}." -f $module.Version)
    return $true
}

$requiredModules = @(
    @{ Name = 'Az.Accounts'; MinimumVersion = '2.12.0' },
    @{ Name = 'Az.Resources'; MinimumVersion = '6.0.0' },
    @{ Name = 'Az.Security'; MinimumVersion = '1.3.0' },
    @{ Name = 'Az.Monitor'; MinimumVersion = '4.5.0' },
    @{ Name = 'Microsoft.Graph'; MinimumVersion = '2.0.0' },
    @{ Name = 'ExchangeOnlineManagement'; MinimumVersion = '3.2.0' },
    @{ Name = 'Microsoft.Online.SharePoint.PowerShell'; MinimumVersion = '16.0.0' },
    @{ Name = 'PnP.PowerShell'; MinimumVersion = '2.2.0' }
)

$missingModules = @()
foreach ($moduleInfo in $requiredModules) {
    if (-not (Test-ModulePresence -Name $moduleInfo.Name -MinimumVersion $moduleInfo.MinimumVersion)) {
        $missingModules += $moduleInfo
    }
}

if ($missingModules.Count -gt 0) {
    Write-Host "\nMissing or outdated modules detected:" -ForegroundColor Yellow
    $missingModules | ForEach-Object { Write-Host ("- {0}" -f $_.Name) -ForegroundColor Yellow }

    if ($InstallMissingModules) {
        Write-Host "\nAttempting to install missing modules..." -ForegroundColor Cyan
        foreach ($moduleInfo in $missingModules) {
            Write-Host ("Installing {0}..." -f $moduleInfo.Name)
            Install-Module -Name $moduleInfo.Name -Scope CurrentUser -Force -AllowClobber
        }
        Write-Host "\nRe-run this script to verify module installation." -ForegroundColor Green
    } else {
        Write-Host "\nRun with -InstallMissingModules to install these modules." -ForegroundColor Yellow
    }
} else {
    Write-Host "\nAll required modules are available." -ForegroundColor Green
}
