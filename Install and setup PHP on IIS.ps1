# Ensure the script is run as administrator
# Self-elevate if not running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
            [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Not running as Administrator. Relaunching with elevation..."
    Start-Process -FilePath "powershell" -Verb RunAs -ArgumentList "-NoExit", "-File", "`"$PSCommandPath`""
    exit
}

# Check execution policy
$executionPolicy = Get-ExecutionPolicy
if ($executionPolicy -in @("Restricted", "AllSigned")) {
    Write-Host "Current Execution Policy: $executionPolicy" -ForegroundColor Yellow
    Write-Host "This script requires at least 'RemoteSigned' execution policy to run."
    
    # Prompt user to temporarily bypass execution policy
    $userInput = Read-Host "Would you like to temporarily set it to 'Bypass' for this session? (Y/N)"
    if ($userInput -match "^[Yy]$") {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Write-Host "Execution policy set to 'Bypass' for this session." -ForegroundColor Green
    } else {
        Write-Host "Exiting script. Please run 'Set-ExecutionPolicy RemoteSigned -Scope CurrentUser' and try again." -ForegroundColor Red
        exit
    }
}

# Detect OS Type
$osVersion = (Get-CimInstance Win32_OperatingSystem).Caption
$isWindowsServer = $osVersion -match "Server"

Write-Host "Detected OS: $osVersion" -ForegroundColor Cyan
if ($isWindowsServer) {
    Write-Host "Running on Windows Server, using ServerManager cmdlets..." -ForegroundColor Yellow
} else {
    Write-Host "Running on Windows 10/11, using WindowsOptionalFeature cmdlets..." -ForegroundColor Yellow
}

# List of IIS features to install
$features = @(
    "IIS-WebServerRole",
    "IIS-WebServer",
    "IIS-CommonHttpFeatures",
    "IIS-HttpErrors",
    "IIS-HttpRedirect",
    "IIS-ApplicationDevelopment",
    "IIS-Security",
    "IIS-RequestFiltering",
    "IIS-Performance",
    "IIS-HttpLogging",
    "IIS-LoggingLibraries",
    "IIS-StaticContent",
    "IIS-DefaultDocument",
    "IIS-DirectoryBrowsing",
    "IIS-WebSockets",
    "IIS-CGI",
    "IIS-ManagementConsole",
    "IIS-ManagementScriptingTools",
    "IIS-ManagementService"
)

# Step 1: Check and Install IIS
Write-Host "Checking IIS installation..." -ForegroundColor Cyan

if ($isWindowsServer) {
    # Windows Server: Use Get-WindowsFeature
    Import-Module ServerManager
    $installedFeatures = Get-WindowsFeature | Where-Object { $_.Installed } | Select-Object -ExpandProperty Name
} else {
    # Windows 10/11: Use Get-WindowsOptionalFeature
    $installedFeatures = (Get-WindowsOptionalFeature -Online) | Where-Object { $_.State -eq "Enabled" } | Select-Object -ExpandProperty FeatureName
}

# Filter features that are not yet installed
$featuresToInstall = $features | Where-Object { $_ -notin $installedFeatures }

if ($featuresToInstall.Count -eq 0) {
    Write-Host "All IIS features are already installed." -ForegroundColor Green
} else {
    Write-Host "Installing missing IIS features..." -ForegroundColor Cyan
    foreach ($feature in $featuresToInstall) {
        Write-Host "Enabling $feature..."
        if ($isWindowsServer) {
            Install-WindowsFeature -Name $feature -IncludeManagementTools
        } else {
            Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart
        }
    }
}

# Step 2: Install required C++ Redistributable (2015-2022 x64) if not installed
$vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
$vcRedistInstaller = "$env:TEMP\vc_redist.x64.exe"

function Test-VCRedistributableInstalled {
    $vcKeys = @(
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
    )

    foreach ($key in $vcKeys) {
        if (Test-Path $key) {
            $vcVersion = (Get-ItemProperty -Path $key).Version
            if ($vcVersion -ge 14.0) {
                return $true
            }
        }
    }
    return $false
}

if (-not (Test-VCRedistributableInstalled)) {
    Write-Host "Downloading and installing Visual C++ Redistributable (2015-2022)..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $vcRedistUrl -OutFile $vcRedistInstaller
    Start-Process -FilePath $vcRedistInstaller -ArgumentList "/quiet", "/norestart" -Wait
    Remove-Item -Path $vcRedistInstaller -Force
} else {
    Write-Host "Visual C++ Redistributable is already installed." -ForegroundColor Green
}

# Step 3: Check if PHP Manager for IIS 2.12 is installed
# Function to check if PHP Manager for IIS is installed
# Function to check if PHP Manager for IIS is installed based on folder existence
function Get-PHPManagerForIIS {
    # Define the expected installation path
    $phpManagerFolderPath = "C:\Program Files\PHP Manager 2 for IIS"
    
    # Check if the folder exists
    if (Test-Path $phpManagerFolderPath) {
        return $true
    }
    
    return $false
}

# Check if PHP Manager for IIS is installed
$phpManagerInstalled = Get-PHPManagerForIIS

if ($phpManagerInstalled) {
    Write-Host "PHP Manager for IIS is already installed."
} else {
    Write-Host "PHP Manager for IIS is not installed. Proceeding with installation..."
    # Insert code here to download and install PHP Manager for IIS
    $phpMgrUrl = "https://github.com/phpmanager/phpmanager/releases/download/v2.12/PHPManagerForIIS_x64.msi"
    $phpMgrInstaller = "$env:TEMP\PHPManagerForIIS_x64.msi"

    # Ensure TLS 1.2 is enabled
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Download PHP Manager
    Write-Host "Downloading PHP Manager for IIS 2.6..."
    try {
        Invoke-WebRequest -Uri $phpMgrUrl -OutFile $phpMgrInstaller -ErrorAction Stop
    } catch {
        Write-Host "Error downloading PHP Manager: $_"
        exit 1
    }

    # Verify download and install
    if (Test-Path $phpMgrInstaller) {
        Write-Host "Installing PHP Manager for IIS 2.6..."
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$phpMgrInstaller`" /quiet /norestart" -Wait
        Remove-Item -Path $phpMgrInstaller -Force
        Write-Host "PHP Manager installation completed!"
    } else {
        Write-Host "Failed to download PHP Manager. Please check your internet connection or try again later."
        exit 1
    }
}
# Step 4 PHP
# Function to check if PHP is installed and return its version
function Get-PHPVersion {
    # Check if PHP is available in the system's PATH
    try {
        $phpCommand = Get-Command php -ErrorAction Stop
        # Get the version of PHP
        $phpVersionOutput = & $phpCommand.Source -v | Select-String -Pattern 'PHP (\d+\.\d+\.\d+)' -AllMatches
        if ($phpVersionOutput) {
            return $phpVersionOutput.Matches.Groups[1].Value
        }
    } catch {
        Write-Host "PHP is not installed or not in the PATH. If not installed please install it from https://windows.php.net/download/" -ForegroundColor Red
        return $null
    }
}

# Function to get PHP binary path and version
function Get-PHPBinaryFolder {
    try {
        # Run php -r "echo PHP_BINARY;" to get PHP binary path
        $phpBinaryPath = php -r "echo PHP_BINARY;" 2>&1

        if ($phpBinaryPath -match "php-cgi\.exe" -or $phpBinaryPath -match "php\.exe") {
            # Extract the folder path by removing the php-cgi.exe part
            $phpBinaryFolder = [System.IO.Path]::GetDirectoryName($phpBinaryPath)
            return $phpBinaryFolder
        } else {
            Write-Host "php-cgi.exe not found in the PHP_BINARY path." -ForegroundColor Red
            return $null
        }
    } catch {
        Write-Host "PHP is not installed or PHP command failed." -ForegroundColor Red
        return $null
    }
}

# Check if PHP is installed and get the version
$phpVersion = Get-PHPVersion

# Check if PHP is installed and the version is 8.2 or higher
if ($phpVersion) {
    Write-Host "PHP version $phpVersion is installed."

    # Compare versions (e.g., checking if PHP is 8.2 or higher)
    $requiredVersion = [Version] "8.2.0"
    $installedVersion = [Version]$phpVersion
    if ($installedVersion -ge $requiredVersion) {
        Write-Host "PHP version is 8.2 or higher." -ForegroundColor Green
    } else {
        Write-Host "PHP version is lower than 8.2. Consider upgrading." -ForegroundColor Red
    }

    # Show message for PHP Manager registration
    $phpBinaryPath = Get-PHPBinaryFolder

    # If the PHP binary path is found, output the result
    if ($phpBinaryPath) {
        Write-Host "Go to IIS Manager and register PHP in PHP Manager for IIS. The PHP path is $($phpBinaryPath)\php-cgi.exe" -ForegroundColor Cyan
        # Now let's make sure that IIS_IUSRS have read access to the php dir
        Write-Host "Let's make sure that the IIS_IUSRS has the proper permissions over the php directory"
        icacls "$($phpBinaryPath)" /grant "IIS_IUSRS:(RX)" /T
    } else {
        Write-Host "PHP binary path could not be determined." -ForegroundColor Red
    }
} else {
    Write-Host "PHP is not installed."
}

# Step 5 IIS URL Rewrite Module

# Function to check if IIS URL Rewrite 2 is installed
function Test-IISURLRewriteInstalled {
    # Determine the correct inetsrv folder path based on the process architecture.
    $inetsrvPath = "$env:windir\System32\inetsrv"
    if (($env:PROCESSOR_ARCHITECTURE -eq "x86") -and $env:PROCESSOR_ARCHITEW6432) {
        # Running 32-bit on a 64-bit OS—use Sysnative to bypass redirection.
        $inetsrvPath = "$env:windir\Sysnative\inetsrv"
    }
    $rewriteDll = Join-Path $inetsrvPath "rewrite.dll"

    if (Test-Path $rewriteDll) {
        Write-Host "IIS URL Rewrite 2 is installed (rewrite.dll found at $rewriteDll)." -ForegroundColor Green
        return $true
    } else {
        Write-Host "IIS URL Rewrite 2 is not installed (rewrite.dll not found at $rewriteDll)." -ForegroundColor Yellow
        return $false
    }
}

# Function to download and install IIS URL Rewrite 2
function Install-IISURLRewrite {
    # URL for IIS URL Rewrite 2 installer
    $urlRewriteUrl = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
    $installerPath = "$env:TEMP\rewrite_amd64_en-US.msi"

    # Check if the installer already exists
    if (-not (Test-Path $installerPath)) {
        # Download the installer if it does not exist
        Write-Host "Downloading IIS URL Rewrite 2..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $urlRewriteUrl -OutFile $installerPath
    } else {
        Write-Host "IIS URL Rewrite 2 installer already downloaded." -ForegroundColor Green
    }

    # Install the IIS URL Rewrite 2 package with verbose output
    Write-Host "Installing IIS URL Rewrite 2..." -ForegroundColor Cyan
    $installProcess = Start-Process msiexec.exe -ArgumentList "/i", $installerPath, "/quiet", "/norestart", "/l*v", "$env:TEMP\rewrite_install_log.txt" -PassThru -Wait

    # Capture installation result
    if ($installProcess.ExitCode -eq 0) {
        Write-Host "IIS URL Rewrite 2 installed successfully!" -ForegroundColor Green
    } else {
        Write-Host "IIS URL Rewrite 2 installation failed." -ForegroundColor Red
        Write-Host "Installation log available at: $env:TEMP\rewrite_install_log.txt" -ForegroundColor Yellow
    }

    # Check if installation was successful
    if (Test-IISURLRewriteInstalled) {
        Write-Host "IIS URL Rewrite 2 installed successfully!" -ForegroundColor Green
    } else {
        Write-Host "IIS URL Rewrite 2 installation failed." -ForegroundColor Red
    }
}

# OpenSSL
Write-Host "Be sure to install OpenSSL for Windows if needed - https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow

# Check if IIS URL Rewrite 2 is installed, if not install it
if (-not (Test-IISURLRewriteInstalled)) {
    Install-IISURLRewrite
}

Start-Process inetmgr
