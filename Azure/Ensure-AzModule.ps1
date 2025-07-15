<#
.SYNOPSIS
Ensures the Az module is installed, imported, and ready to use.

.DESCRIPTION
Use this script at the top of your PowerShell scripts to check for the Az module,
install it if necessary (current user scope), and validate version requirements.
Works on PowerShell 5.1 and PowerShell Core (7+).
#>

# Minimum required version (customize as needed)
$MinimumAzVersion = [Version]"12.5.0"

# Check PowerShell version (optional warning)
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Warning "This script requires PowerShell 5.1 or later."
    exit 1
}

# Check if Az module is already installed
$azModule = Get-InstalledModule -Name Az -ErrorAction SilentlyContinue

if (-not $azModule) {
    Write-Host "Az module not found. Installing for current user..."

    try {
        # Register PSGallery if not trusted
        if (-not (Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue).InstallationPolicy -eq "Trusted") {
            Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction Stop
        }

        Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force -ErrorAction Stop
        Write-Host "Az module installed successfully."
    } catch {
        Write-Error "Failed to install Az module: $_"
        exit 1
    }
} else {
    # Check version
    if ($azModule.Version -lt $MinimumAzVersion) {
        Write-Warning "Az module version $($azModule.Version) is less than required version $MinimumAzVersion."
        Write-Warning "Please update using: Update-Module -Name Az -Scope CurrentUser"
    }
}

# Check if Az module is already loaded
if (-not (Get-Module -ListAvailable -Name Az)) {
    Write-Error "Az module is not available even after installation."
    exit 1
}

# Prevent double import or conflict
$azLoaded = Get-Module -Name Az -All | Where-Object { $_.FullyQualifiedName }
if (-not $azLoaded) {
    try {
        Import-Module -Name Az -MinimumVersion $MinimumAzVersion -ErrorAction Stop
        Write-Host "Az module imported successfully."
    } catch {
        Write-Error "Failed to import Az module: $_"
        exit 1
    }
} else {
    Write-Host "Az module is already loaded, skipping import."
}

# Test Az module usability (e.g., Az.Accounts loaded)
if (-not (Get-Command -Module Az.Accounts -Name Connect-AzAccount -ErrorAction SilentlyContinue)) {
    Write-Error "Az module does not seem to be fully functional."
    exit 1
}

Write-Verbose "Az module is ready to use." -Verbose
