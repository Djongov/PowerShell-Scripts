# =============================================== Control Panel ===============================================
# Number of days to check for expiration
$expiryCheckInDays = 40

# When looking for GetCertificates Arc VMs jobs, what is the value in days since the job was last run, in order to run it again
$lookForDaysLastRunArcGetCertificatesCommand = 30

$useInAutomationAccount = $false # Set to true if you want to run this script in Azure Automation Account

$runInBastion = $false # Set to true if you want to run this in the Azure Bastion, cannot be true if $useInAutomationAccount is true

$emailReport = $false # Set to true if you want to send the report via email

# Define the email recipients for the report when running in Azure Automation Account
$automationAccontEmailRecipients = "xxx@xxx.com"

$saveReportLocally = $true # Set to true if you want to save the report locally

$saveReportToStorage = $false # Set to true if you want to save the report to a storage account

$saveOutputToFile = $false # Set to true if you want to save the output of the script to a file

# Define Resource Types That Hold SSL Certificates
$resourceTypes = @(
    "Microsoft.KeyVault/vaults" # Key Vaults
    "Microsoft.Web/sites" # Web Apps
    "Microsoft.CertificateRegistration/certificateOrders" # App Service Certificates
    "Microsoft.Network/applicationGateways" # Application Gateways
    "Microsoft.Cdn/profiles" # Front Door CDN profiles
    "Microsoft.ApiManagement/service" # APIM
    "Microsoft.App/managedEnvironments" # Container App Environments
    #"Microsoft.HybridCompute/machines" # Azure Arc Machines
    #"Microsoft.Compute/virtualMachines" # Azure VMs
)

# Here we give us a chance to exclude some subscriptions from the check
$excludedSubscriptions = @(
    # "Subscription Name 1"
)

$htmlFontColor = "#005EB4"

# Upload to storage account too
$storageAccountName = "XXX"
$containerName = "xxx"

# =============================================== Settings ===============================================
# Do a small check if $runInBastion and $useInAutomationAccount are both true as they shouldn't be
if ($useInAutomationAccount -eq $true -and $runInBastion -eq $true) {
    Write-Error "useInAutomationAccount and runInBastion are both True. Only one of them can be set to True"
    exit
}

if ($useInAutomationAccount) {
    $preferedCli = $true # Set to true if you want raw Output or false if you want Write-Host
} else {
    $preferedCli = $false # Set to true if you want raw Output or false if you want Write-Host
}

$log = @() # Initialize log array

$ErrorActionPreference = "Stop"
# =============================================== Functions ===============================================
# Function to build Html table from array of objects
function ConvertTo-HtmlTable {
    param (
        [Parameter(Mandatory = $true)]
        [Array]$Certificates
    )

    if ($Certificates.Count -eq 0) {
        return "<p>No certificates found.</p>"
    }

    $Certificates = $Certificates | Group-Object -Property Thumbprint | ForEach-Object { $_.Group[0] }

    # Get all unique keys from the first object
    $keys = $Certificates[0].PSObject.Properties.Name

    # Default style for th and td
    $baseStyle = "border: 1px solid;padding: 5px;"

    # Start table
    $html = "<table style='border: 1px solid; border-collapse: collapse; margin-bottom: 10px;text-align: center;'>"

    # Generate table headers
    $html += "<tr>"
    foreach ($key in $keys) {
        $html += "<th style='$baseStyle background-color: #f2f2f2;'>$key</th>"
    }
    $html += "</tr>"

    # Generate table rows
    foreach ($cert in $Certificates) {
        $html += "<tr>"
        foreach ($key in $keys) {
            $value = $cert.$key -replace "<", "&lt;" -replace ">", "&gt;"  # Sanitize HTML

            # Reset cell style for each cell
            $cellStyle = $baseStyle

            # Apply conditional coloring for "DaysUntilExpired"
            if ($key -eq "DaysUntilExpired" -and $null -ne $cert.$key -and $cert.$key -match "^-?\d+$") {
                $days = [int]$cert.$key # Convert to integer

                if ($days -le 15) {
                    $cellStyle += " background-color: red; color: white;"
                } elseif ($days -le 30) {
                    $cellStyle += " background-color: yellow; color: black;"
                } else {
                    $cellStyle += " background-color: green; color: white;"
                }
            }            

            $html += "<td style='$cellStyle'>$value</td>"
        }
        $html += "</tr>"
    }

    # Close table
    $html += "</table>"

    return $html
}
# This is a function to decide whether we write output or write-host easily
function PrintMessage {
    param (
        [Parameter(Mandatory = $true)]
        [string]$M,
        [Parameter(Mandatory = $false)]
        [string]$Color = "White"
    )

    # Store message in script-level log
    $script:log += $M

    if ($preferedCli) {
        Write-Output $M
    } else {
        Write-Host $M -ForegroundColor $Color
    }
}
# =============================================== Modules ===============================================
# Define an array of required module names
$requiredModules = @('Az.App', 'Az', 'Az.ConnectedMachine')

if ($useInAutomationAccount) {
    $requiredModules += 'Az.Automation'
}

# Loop through each module in the array and check if it's imported
foreach ($module in $requiredModules) {
    PrintMessage -M "Importing $module"
    Import-Module -Name $module
}
# =============================================== AUTHENTICATION ===============================================
. "$(Join-Path -Path $PSScriptRoot -ChildPath './Check-Az-Context.ps1')"
# =============================================== VARIABLES ===============================================
# Initialize HTML string
$html = ''

# Define the arrays to store the certificates of each type
$keyVaultCertificates = @()
$keyVaultSecrets = @()
$AppServiceCertificates = @()
$webAppCertificates = @()
$appGatewayCertificates = @()
$frontDoorSecrets = @()
$apimCetificates = @()
$containerEnvironmentCertificates = @()
$azureArcVMCertificates = @()
$azureVMCertificates = @()

# Errors
$azureVMsWithWinRMError = @()
$azureVMsNoDns = @()

# Access Failures - tracking resources we couldn't access
$accessFailures = @()

# Extra
$webAppsWithMissingCertificates = @()
# =============================================== ACTUAL WORK ===================================================
PrintMessage -M "=================================================== Starting script ===================================================" -Color Green

# Get All Available Subscriptions
$subscriptions = Get-AzSubscription

# Filter out the excluded subscriptions
$subscriptionsToProcess = $subscriptions | Where-Object { $_.Name -notin $excludedSubscriptions }

# Loop Through Each Subscription based on the filtered subscriptions
foreach ($sub in $subscriptionsToProcess) {
    PrintMessage -M "Switching to subscription: $($sub.Name) ($($sub.Id))" -Color Blue
    Set-AzContext -SubscriptionId $sub.Id > $null 2>&1 # Suppress output

    # Loop Through Each Resource Type
    foreach ($resourceType in $resourceTypes) {
        PrintMessage -M "==================================== Fetching resources of type: $resourceType in subscription $($sub.Name) ====================================" -Color Yellow
        
        # Pull all resources of the current type
        $resources = Get-AzResource -ResourceType $resourceType

        # There very well may be no resources of the current type in the subscription
        if ($resources.Count -eq 0) {
            PrintMessage -M "No resources of type $resourceType found in subscription $($sub.Name)" -Color Yellow
            continue
        }

        # Loop through each resource of the current type found in that subscription
        foreach ($resource in $resources) {
            # We will use switch statement to handle each resource type differently based on the resource type
            switch ($resourceType) {
                # Key Vault Certificates
                "Microsoft.KeyVault/vaults" {
                    PrintMessage -M "Checking Key Vault: $($resource.Name)" -Color Magenta
                    PrintMessage -M "Checking for Certificates in Key Vault: $($resource.Name)" -Color Yellow
                    # Pull all certificates in the key vault
                    try {
                        $certs = Get-AzKeyVaultCertificate -VaultName $resource.Name -ErrorAction Stop
                        if ($certs) {
                            foreach ($cert in $certs) {
                                try {
                                    $currentCertificate = Get-AzKeyVaultCertificate -VaultName $resource.Name -Name $cert.Name -ErrorAction Stop
                                    if ($currentCertificate.Expires -le (Get-Date).AddDays($expiryCheckInDays)) {
                                        PrintMessage -M "Found certificate that expires within the set deadline in KeyVault $($resource.Name). Certificate $($currentCertificate.Name) | Expiration $($currentCertificate.Expires) | Thumbprint $($currentCertificate.Thumbprint)" -Color Red
                                        # Add the certificate to the collection
                                        $keyVaultCertificates += [PSCustomObject]@{
                                            SubscriptionName = $sub.Name
                                            VaultName        = $resource.Name
                                            Name             = $currentCertificate.Name
                                            Expires          = $currentCertificate.Expires
                                            DaysUntilExpired = ($currentCertificate.Expires - (Get-Date)).Days
                                            Thumbprint       = $currentCertificate.Thumbprint
                                        }
                                    }
                                } catch {
                                    PrintMessage -M "Failed to get certificate '$($cert.Name)' from Key Vault '$($resource.Name)': $($_.Exception.Message)" -Color Red
                                    $accessFailures += [PSCustomObject]@{
                                        SubscriptionName = $sub.Name
                                        ResourceType     = "Microsoft.KeyVault/vaults"
                                        ResourceName     = $resource.Name
                                        Operation        = "Get-AzKeyVaultCertificate (individual)"
                                        Error            = $_.Exception.Message
                                    }
                                }
                            }
                        } else {
                            PrintMessage -M "No certificates found in Key Vault: $($resource.Name)"
                        }
                    } catch {
                        PrintMessage -M "Failed to list certificates in Key Vault '$($resource.Name)': $($_.Exception.Message)" -Color Red
                        $accessFailures += [PSCustomObject]@{
                            SubscriptionName = $sub.Name
                            ResourceType     = "Microsoft.KeyVault/vaults"
                            ResourceName     = $resource.Name
                            Operation        = "Get-AzKeyVaultCertificate (list)"
                            Error            = $_.Exception.Message
                        }
                    }
                    
                    # Now pull all secrets in the key vault (this may be a redundant check, might remove later)
                    PrintMessage -M "Checking for Certificate Secrets in Key Vault: $($resource.Name)" -Color Yellow
                    try {
                        $secrets = Get-AzKeyVaultSecret -VaultName $resource.Name -ErrorAction Stop
                        if ($secrets) {
                            foreach ($secret in $secrets) {
                                if ($null -ne $secret.Attributes.Expires) {
                                    if ($secret.Attributes.Expires -le (Get-Date).AddDays($expiryCheckInDays)) {
                                        PrintMessage -Message "Found secret that expires within the set deadline: $($resource.Name)" -Color Red
                                        # Add the certificate to the collection
                                        $keyVaultSecrets += [PSCustomObject]@{
                                            SubscriptionName = $sub.Name
                                            VaultName        = $resource.Name
                                            Name             = $secret.Name
                                            Expires          = $secret.Attributes.Expires
                                            DaysUntilExpired = ($secret.Attributes.Expires - (Get-Date)).Days
                                            Thumbprint       = $secret.Attributes.Thumbprint
                                        }
                                    }
                                }
                            }
                        } else {
                            PrintMessage -M "No certificate secrets found in Key Vault: $($resource.Name)"
                        }
                    } catch {
                        PrintMessage -M "Failed to list secrets in Key Vault '$($resource.Name)': $($_.Exception.Message)" -Color Red
                        $accessFailures += [PSCustomObject]@{
                            SubscriptionName = $sub.Name
                            ResourceType     = "Microsoft.KeyVault/vaults"
                            ResourceName     = $resource.Name
                            Operation        = "Get-AzKeyVaultSecret"
                            Error            = $_.Exception.Message
                        }
                    }
                }
                # App Service Certificates
                "Microsoft.CertificateRegistration/certificateOrders" {
                    try {
                        # So App Service Certificate expirations are hidden under the properties of the resource, so we need to expand the properties to get the expiration date
                        $ascResource = Get-AzResource -ResourceType "Microsoft.CertificateRegistration/certificateOrders" -Name $resource.Name -ResourceGroupName $resource.ResourceGroupName -ExpandProperties -ErrorAction Stop
                        $expiryDate = $ascResource.Properties.expirationTime
                        PrintMessage -M "Checking Certificate Registration: $($resource.Name) | Expiry: $expiryDate" -Color Yellow
                        if ($expiryDate -le (Get-Date).AddDays($expiryCheckInDays)) {
                            PrintMessage -M "Found Certificate Registration that expires within the set deadline: $($resource.Name)" -Color Red
                            # Add the certificate to the collection
                            $AppServiceCertificates += [PSCustomObject]@{
                                SubscriptionName = $sub.Name
                                VaultName        = $resource.ResourceGroupName
                                Name             = $resource.Name
                                Expires          = $expiryDate
                                DaysUntilExpired = ($expiryDate - (Get-Date)).Days
                                Thumbprint       = $ascResource.Properties.signedCertificate.thumbprint
                            }
                        }
                    } catch {
                        PrintMessage -M "Failed to get App Service Certificate '$($resource.Name)': $($_.Exception.Message)" -Color Red
                        $accessFailures += [PSCustomObject]@{
                            SubscriptionName = $sub.Name
                            ResourceType     = "Microsoft.CertificateRegistration/certificateOrders"
                            ResourceName     = $resource.Name
                            Operation        = "Get-AzResource"
                            Error            = $_.Exception.Message
                        }
                    }
                }
                # Application Gateway Certificates
                "Microsoft.Network/applicationGateways" {
                    # Here is when it gets tricky, none of the Azure APIs or PowerShell or az cli commands return the expiration date of the certificate, so we need to decode the certificate ourselves
                    foreach ($resource in $resources) {
                        try {
                            # first let's pull the actual application gateway data
                            $appGateway = Get-AzApplicationGateway -ResourceGroupName $resource.ResourceGroupName -Name $resource.Name -ErrorAction Stop
                            # Now let's pull the certificates from the application gateway
                            $Certs = Get-AzApplicationGatewaySslCertificate -ApplicationGateway $appGateway -ErrorAction Stop
                        } catch {
                            PrintMessage -M "Failed to get Application Gateway '$($resource.Name)': $($_.Exception.Message)" -Color Red
                            $accessFailures += [PSCustomObject]@{
                                SubscriptionName = $sub.Name
                                ResourceType     = "Microsoft.Network/applicationGateways"
                                ResourceName     = $resource.Name
                                Operation        = "Get-AzApplicationGateway"
                                Error            = $_.Exception.Message
                            }
                            continue
                        }

                        foreach ($cert in $Certs) {
                            PrintMessage -M "Processing certificate: $($cert.Name) in Application Gateway: $($appGateway.Name)" -Color Yellow

                            # First thing we want to check is if the certificate is stored in Key Vault or not. If it is stored in key vault, we will not have any data to decode
                            if ($null -ne $cert.KeyVaultSecretId) {
                                PrintMessage -M "Certificate is stored in Key Vault: $($cert.KeyVaultSecretId)"
                                try {
                                    # Because these are not exposed 
                                    $keyVaultName = $cert.KeyVaultSecretId.Split('/')[2]
                                    $keyVaultName = $keyVaultName.Split('.')[0]
                                    $keyVaultsecretName = $cert.KeyVaultSecretId.Split('/')[4]
                                    $keyVaultSecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $keyVaultsecretName -ErrorAction Stop
                                    $expirationDate = $keyVaultSecret.Attributes.Expires
                                    # So on some certificates it turns out that thumbprint is in tags
                                    if ($null -ne $keyVaultSecret.Tags.Thumbprint) {
                                        $thumbprint = $keyVaultSecret.Tags.Thumbprint
                                        # If the thumbprint is not in tags, then we will use the thumbprint property
                                        if (!$thumbprint) {
                                            $thumbprint = $keyVaultSecret.Properties.Tags.Thumbprint
                                        }
                                    }
                                } catch {
                                    PrintMessage -M "Failed to get Key Vault secret for Application Gateway certificate '$($cert.Name)': $($_.Exception.Message)" -Color Red
                                    $accessFailures += [PSCustomObject]@{
                                        SubscriptionName = $sub.Name
                                        ResourceType     = "Microsoft.Network/applicationGateways"
                                        ResourceName     = $resource.Name
                                        Operation        = "Get-AzKeyVaultSecret (for cert: $($cert.Name))"
                                        Error            = $_.Exception.Message
                                    }
                                    continue
                                }
                            } else {
                                # If it is not a key vault SecretId, then it is a base64 encoded certificate
                                PrintMessage -M "Certificate is not stored in Key Vault, decoding certificate data" -Color Yellow
                                # Decode the base64 certificate data into a byte array
                                $decodedBytes = [System.Convert]::FromBase64String($cert.PublicCertData)

                                # Convert the byte array to a string for regex matching, we search for strings that look like dates
                                $decodedString = [System.Text.Encoding]::UTF8.GetString($decodedBytes)

                                # Regular expression to match dates in the format YYMMDDHHMMSSZ
                                $pattern = '\d{6}\d{6}Z'

                                # Find all possible dates in the decoded string using the regex pattern
                                $foundPossibleDates = [regex]::Matches($decodedString, $pattern)

                                # 0 index is usually the start date, 1 index is usually the expiration date
                                $expirationInZulu = $foundPossibleDates[1].Value.TrimEnd('Z')

                                # Parse the expiration date in Zulu format to a datetime object so we can use it for comparison if expired
                                $expirationDate = [datetime]::ParseExact($expirationInZulu, "yyMMddHHmmss", $null)

                                # Compute the SHA1 thumbprint manually using the decoded bytes. This does not produce the same thumbprint as the certificate object in Azure but for our comparison purposes it is enough
                                $sha1 = [System.Security.Cryptography.SHA1]::Create()
                                $thumbprintBytes = $sha1.ComputeHash($decodedBytes)
                                $thumbprint = ([System.BitConverter]::ToString($thumbprintBytes) -replace '-', '').ToUpper()
                            }

                            # So now we have expirations and thumbprints from the two possible sources, let's make the comparisons

                            PrintMessage -M "Certificate: $($cert.Name) | Expiry: $expirationDate | Thumbprint: $thumbprint. Checking if expired" -Color Yellow

                            # If the certificate expires soon, add it to the collection (example condition below)
                            if ($expirationDate -le (Get-Date).AddDays($expiryCheckInDays)) {
                                PrintMessage -M "Found Application Gateway certificate that expires within the set deadline: $($resource.Name)" -Color Red
                                # Use if else and not ternary so we can support ISE powershell
                                if ($null -eq $cert.keyVaultSecretId) {
                                    $VaultName = "Manually Uploaded"
                                } else {
                                    $VaultName = $cert.KeyVaultSecretId
                                }
                                # Add the certificate to the collection
                                $appGatewayCertificates += [PSCustomObject]@{
                                    SubscriptionName = $sub.Name
                                    AppGatewayName   = $resource.Name
                                    VaultName        = $VaultName
                                    Name             = $cert.Name
                                    Expires          = $expirationDate
                                    DaysUntilExpired = ($expirationDate - (Get-Date)).Days
                                    Thumbprint       = $thumbprint
                                }
                            }
                        }
                    }
                }
                # Front Door CDN Secrets
                "Microsoft.Cdn/profiles" {
                    foreach ($resource in $resources) {
                        PrintMessage -M "Checking Front Door CDN Profile: $($resource.Name)" -Color Magenta

                        try {
                            # Get the secrets for the front door profile
                            $secrets = Get-AzFrontDoorCdnSecret -ProfileName $resource.Name -ResourceGroupName $resource.ResourceGroupName -ErrorAction Stop
                        } catch {
                            PrintMessage -M "Failed to get Front Door CDN secrets for '$($resource.Name)': $($_.Exception.Message)" -Color Red
                            $accessFailures += [PSCustomObject]@{
                                SubscriptionName = $sub.Name
                                ResourceType     = "Microsoft.Cdn/profiles"
                                ResourceName     = $resource.Name
                                Operation        = "Get-AzFrontDoorCdnSecret"
                                Error            = $_.Exception.Message
                            }
                            continue
                        }

                        foreach ($secret in $secrets) {
                            PrintMessage -M "Processing secret $($secret.Name)"
                            # The secrets are hidden within the parameters of the secret, so we need to decode the JSON to get the expiration date and thumbprint
                            $paramsJson = $secret.Parameter | ConvertFrom-Json
                            $expiryDate = $paramsJson.expirationDate
                            $thumbprint = $paramsJson.thumbprint

                            if ($expiryDate -le (Get-Date).AddDays($expiryCheckInDays)) {
                                PrintMessage -M "Found Front Door CDN secret that expires within the set deadline: $($resource.Name) | Expiration $($expiryDate) | Thumbprint $($thumbprint)" -Color Red
                                # Add the certificate to the collection
                                $frontDoorSecrets += [PSCustomObject]@{
                                    SubscriptionName        = $sub.Name
                                    FrontDoorName           = $resource.Name
                                    SecretName              = $secret.Name
                                    UseLatestVersion        = [string]$paramsJson.UseLatestVersion
                                    VaultName               = ($paramsJson.secretSource.id).Split('/')[8]
                                    Expires                 = $expiryDate
                                    DaysUntilExpired        = ($expiryDate - (Get-Date)).Days
                                    Thumbprint              = $thumbprint
                                }
                            }
                        }
                    }
                }
                # APIM Certificates
                "Microsoft.ApiManagement/service" {
                    try {
                        # So APIM certificates are a bit tricky, because they are not directly exposed in the API, turns out that they sit in the ProxyCustomHostnameConfiguration property of the APIM object
                        $apim = Get-AzApiManagement -ResourceGroupName $resource.ResourceGroupName -Name $resource.Name -ErrorAction Stop
                        # Get the CustomHostnameConfiguration property
                        $certs = $apim.ProxyCustomHostnameConfiguration
                    } catch {
                        PrintMessage -M "Failed to get APIM service '$($resource.Name)': $($_.Exception.Message)" -Color Red
                        $accessFailures += [PSCustomObject]@{
                            SubscriptionName = $sub.Name
                            ResourceType     = "Microsoft.ApiManagement/service"
                            ResourceName     = $resource.Name
                            Operation        = "Get-AzApiManagement"
                            Error            = $_.Exception.Message
                        }
                        continue
                    }

                    foreach ($cert in $certs) {
                        # So there are certificates that are built in and we don't care about them as they are azure managed
                        if ($cert.CertificateSource -ne "BuiltIn" -or -not $object.CertificateInformation) {

                            # The certificate information is hidden in the CertificateInformation property
                            $certData = $cert.CertificateInformation

                            if (!$certData) {
                                PrintMessage -M "Skipping because the certificate might be built-in. $($certData)" -Color Red
                                continue
                            }
                            # Extract the data we need
                            $expiryDate = $certData.Expiry
                            $thumbprint = $certData.Thumbprint

                            if ($expiryDate -le (Get-Date).AddDays($expiryCheckInDays)) {
                                PrintMessage -M "Found APIM certificate that expires within the set deadline in $($resource.Name). Certificate: $($cert.Hostname) | Expiry: $($expiryDate) | Thumbprint: $($thumbprint)" -Color Red
                                # Use if else and not ternary so we can support ISE powershell
                                if ($cert.KeyVaultId) {
                                    $VaultName = $cert.KeyVaultId
                                } else {
                                    $VaultName = "Manually Uploaded"
                                }
                                # Add the certificate to the collection
                                $apimCetificates += [PSCustomObject]@{
                                    SubscriptionName = $sub.Name
                                    ApimName         = $resource.Name
                                    Domain           = $cert.Hostname
                                    KeyVaultName     = $VaultName  # If the certificate is stored in Key Vault, we will have the ID here
                                    Expires          = $expiryDate
                                    DaysUntilExpired = ($expiryDate - (Get-Date)).Days
                                    Thumbprint       = $thumbprint
                                }
                            }
                        }
                    }
                }
                # Container App Environment Certificates
                "Microsoft.App/managedEnvironments" {
                    try {
                        # Pull directly the certficiates from the container app environment, we have the cmdlet for that (thanks)
                        $certs = Get-AzContainerAppManagedEnvCert -EnvName $resource.Name -ResourceGroupName $resource.ResourceGroupName -ErrorAction Stop
                    } catch {
                        PrintMessage -M "Failed to get Container App Environment certificates for '$($resource.Name)': $($_.Exception.Message)" -Color Red
                        $accessFailures += [PSCustomObject]@{
                            SubscriptionName = $sub.Name
                            ResourceType     = "Microsoft.App/managedEnvironments"
                            ResourceName     = $resource.Name
                            Operation        = "Get-AzContainerAppManagedEnvCert"
                            Error            = $_.Exception.Message
                        }
                        continue
                    }
                    foreach ($cert in $certs) {
                        $cert.Name
                        $cert.Thumbprint
                        $cert.ExpirationDate

                        if ($cert.ExpirationDate -le (Get-Date).AddDays($expiryCheckInDays)) {
                            PrintMessage -M "Found Container App Environment certificate that expires within the set deadline in $($resource.Name). Certificate: $($cert.Name) | Expiry: $($cert.ExpirationDate) | Thumbprint: $($cert.Thumbprint)" -Color Red
                            $containerEnvironmentCertificates += [PSCustomObject]@{
                                SubscriptionName = $sub.Name
                                EnvName          = $resource.Name
                                Name             = $cert.Name
                                Expires          = $cert.ExpirationDate
                                DaysUntilExpired = ($cert.ExpirationDate - (Get-Date)).Days
                                Thumbprint       = $cert.Thumbprint
                            }
                        }
                    }
                }
                # Azure Arc VMs
                "Microsoft.HybridCompute/machines" {
                    # For each ARC VM, we need to get its details
                    PrintMessage -M "Checking Azure Arc VM: $($resource.Name) in Resource Group $($resource.ResourceGroupName)" -Color Yellow
                    try {
                        $arcVMDetails = Get-AzConnectedMachine -Name $resource.Name -ResourceGroupName $resource.ResourceGroupName -ErrorAction Stop
                    } catch {
                        PrintMessage -M "Failed to get Azure Arc VM details for '$($resource.Name)': $($_.Exception.Message)" -Color Red
                        $accessFailures += [PSCustomObject]@{
                            SubscriptionName = $sub.Name
                            ResourceType     = "Microsoft.HybridCompute/machines"
                            ResourceName     = $resource.Name
                            Operation        = "Get-AzConnectedMachine"
                            Error            = $_.Exception.Message
                        }
                        continue
                    }

                    if ($arcVMDetails.Status -eq "Disconnected" -or $null -eq $arcVMDetails.Status -or $arcVMDetails.Status -eq "Expired") {
                        PrintMessage -M "Azure Arc VM: $($arcVMDetails.Name) is $($arcVMDetails.Status). Skipping..." -Color Red
                        continue
                    }

                    # If it is Windows, we can run a command to get the certificates
                    if ($arcVMDetails.OSType -eq "windows") {
                        PrintMessage -M "$($resource.Name) is a Windows machine"
                        # Let's list the runCommands available on the machine
                        PrintMessage -M "Looking for available commands on Azure Arc VM: $($arcVMDetails.Name) in Resource Group: $($arcVMDetails.ResourceGroupName)" -Color Yellow

                        try {
                            $getCertificatesCommand = Get-AzConnectedMachineRunCommand -ResourceGroupName $resource.ResourceGroupName -MachineName $resource.Name -RunCommandName "GetCertificates"
                        } catch {
                            PrintMessage -M "Error getting run command: $($_.Exception.Message)" -Color Red
                            PrintMessage -M "No GetCertificates command found on Azure Arc VM: $($arcVMDetails.Name) in Resource Group: $($arcVMDetails.ResourceGroupName). Running it" -Color Red
                            $runCommand = New-AzConnectedMachineRunCommand -ResourceGroupName $resource.ResourceGroupName -MachineName $resource.Name -Location "West Europe" -RunCommandName "GetCertificates" –SourceScript "Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Thumbprint, Subject, NotAfter, NotBefore, Issuer"
                        }

                        
                        PrintMessage -M "GetCertificate command is found and is in $($getCertificatesCommand.InstanceViewExecutionState) state"
                        if ($getCertificatesCommand.InstanceViewExecutionState.InstanceViewExecutionState -eq "Failed") {
                            PrintMessage -M "Command $($getCertificatesCommand.Name) is in Failed state. Running it again" -Color Red
                            $runCommand = New-AzConnectedMachineRunCommand -ResourceGroupName $resource.ResourceGroupName -MachineName $resource.Name -Location "West Europe" -RunCommandName "GetCertificates" –SourceScript "Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Thumbprint, Subject, NotAfter, NotBefore, Issuer"
                        } else {
                            PrintMessage -M "Command $($getCertificatesCommand.Name) is in $($getCertificatesCommand.InstanceViewExecutionState) state"
                            # If the state of the command is OK, let's see when it ran for the last time (InstanceViewEndTime) and compared it to today. If it has last run more than 7 days ago
                            $rawDate = $runCommand.InstanceViewEndTime

                            # Ensure the date is valid
                            if ($rawDate -and $rawDate -ne '-' -and $rawDate -match '\d{1,2}/\d{1,2}/\d{4} \d{2}:\d{2}:\d{2}') {
                                try {
                                    $lastRun = [DateTime]::ParseExact($rawDate, 'MM/dd/yyyy HH:mm:ss', $null)
                                    if ($lastRun -is [DateTime]) {
                                        $daysSinceLastRun = (New-TimeSpan -Start $lastRun -End (Get-Date)).Days
                                    } else {
                                        throw "Parsed date is not a valid DateTime"
                                    }
                                } catch {
                                    PrintMessage -M "Failed to parse date: $($_.Exception.Message)" -Color Red
                                    $daysSinceLastRun = $null
                                }
                            } else {
                                PrintMessage -M "Invalid date format or empty: '$rawDate'" -Color Red
                                $daysSinceLastRun = $null
                            }

                            PrintMessage -M "Checking if the last run was within $($lookForDaysLastRunArcGetCertificatesCommand) days"
                            if ($daysSinceLastRun -gt $lookForDaysLastRunArcGetCertificatesCommand) {
                                PrintMessage -M "Last run was longer than $($lookForDaysLastRunArcGetCertificatesCommand) days ago ($($lastRun)). Running the command again" -Color Red
                                $runCommand = New-AzConnectedMachineRunCommand -ResourceGroupName $resource.ResourceGroupName -MachineName $resource.Name -Location "West Europe" -RunCommandName "GetCertificates" –SourceScript "Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Thumbprint, Subject, NotAfter, NotBefore, Issuer" -ErrorAction SilentlyContinue
                            } else {
                                PrintMessage -M "Last run was within $($lookForDaysLastRunArcGetCertificatesCommand) days. Pulling the last run data"
                                # Then we can pull the last run and read from it instead of calling again (because the New-AzConnectedMachineRunCommand is a slow operation)
                                $runCommand = Get-AzConnectedMachineRunCommand -ResourceGroupName $resource.ResourceGroupName -MachineName $resource.Name -RunCommandName "GetCertificates" -ErrorAction SilentlyContinue
                            }
                        }
                        
                        $vmCertificates = $runCommand.InstanceViewOutput -replace "`r", ""  # Normalize newlines
                        $vmCertificatesArray = $vmCertificates -split "`n" | Where-Object { $_ -match "\S" }

                        # Create an array to hold certificate objects
                        $certificates = @()

                        # Temporary variables to store certificate details
                        $cert = $null
                        $certThumbprint = $certSubject = $certNotAfter = $certNotBefore = $certIssuer = ""

                        foreach ($line in $vmCertificatesArray) {
                            if ($line -match "^Thumbprint\s*:\s*(.+)$") {
                                if ($certThumbprint) {
                                    # Save the previous certificate before moving on to the next one
                                    $cert = [PSCustomObject]@{
                                        Thumbprint = $certThumbprint
                                        Subject    = $certSubject
                                        NotAfter   = $certNotAfter
                                        NotBefore  = $certNotBefore
                                        Issuer     = $certIssuer
                                    }
                                    $certificates += $cert
                                }

                                # Start a new certificate
                                $certThumbprint = $matches[1]
                                $certSubject = $certNotAfter = $certNotBefore = $certIssuer = ""
                            }
                            elseif ($line -match "^Subject\s*:\s*(.+)$") {
                                $certSubject = $matches[1]
                            }
                            elseif ($line -match "^NotAfter\s*:\s*(.+)$") {
                                $certNotAfter = if ($matches[1] -ne "-") { $matches[1] } else { $null }
                            }
                            elseif ($line -match "^NotBefore\s*:\s*(.+)$") {
                                $certNotBefore = if ($matches[1] -ne "-") { $matches[1] } else { $null }
                            }
                            elseif ($line -match "^Issuer\s*:\s*(.+)$") {
                                $certIssuer = $matches[1]
                            }
                        }

                        # Add the last certificate
                        if ($certThumbprint) {
                            $cert = [PSCustomObject]@{
                                Thumbprint = $certThumbprint
                                Subject    = $certSubject
                                NotAfter   = $certNotAfter
                                NotBefore  = $certNotBefore
                                Issuer     = $certIssuer
                            }
                            $certificates += $cert
                        }

                        # Now you can access the certificates as objects
                        foreach ($cert in $certificates) {
                            # Convert the NotAfter value to a DateTime object
                            PrintMessage -M "Found a certificate - Issuer: $($cert.Issuer), Subject: $($cert.Subject), Thumbprint: $($cert.Thumbprint), Expiry: $($cert.NotAfter)"
                            try {
                                $expiry = [DateTime]$cert.NotAfter
                                
                                # Perform the expiry check
                                if ($expiry -le (Get-Date).AddDays($expiryCheckInDays)) {
                                    PrintMessage -M "Found a certificate that expires within the set deadline - Issuer: $($cert.Issuer), Subject: $($cert.Subject), Thumbprint: $($cert.Thumbprint), Expiry: $($expiry)" -Color Red
                                    
                                    # Add certificate to the array with proper DateTime comparison
                                    $azureArcVMCertificates += [PSCustomObject]@{
                                        ArcVM            = $arcVMDetails.Name
                                        ResourceGroup    = $arcVMDetails.ResourceGroupName
                                        Name             = $arcVMDetails.Name
                                        Issuer           = $cert.Issuer
                                        Subject          = $cert.Subject
                                        Expires          = $expiry
                                        DaysUntilExpired = ($expiry - (Get-Date)).Days
                                        Thumbprint       = $cert.Thumbprint
                                    }
                                } else {
                                    PrintMessage -M "Certificate is not expiring within the set deadline limit"
                                }
                            } catch {
                                PrintMessage -M "Error parsing NotAfter ($($cert.NotAfter)) for certificate with Thumbprint $($cert.Thumbprint): $_" -Color Red
                            }
                        }
                    } else {
                        #PrintMessage -M "Machine is $($arcVMDetails.OSType)" -Color Red
                    }
                }
                # Azure VMs
                "Microsoft.Compute/virtualMachines" {
                    PrintMessage -M "============================================================================"
                    PrintMessage -M "Checking $($resource.Name) in Resource Group $($resource.ResourceGroupName)" -Color Yellow
                    try {
                        $vm = Get-AzVM -ResourceGroupName $resource.ResourceGroupName -Name $resource.Name -ErrorAction Stop

                        $powerState = (Get-AzVM -ResourceGroupName $resource.ResourceGroupName -Name $resource.Name -Status -ErrorAction Stop).Statuses[1].Code
                    } catch {
                        PrintMessage -M "Failed to get Azure VM details for '$($resource.Name)': $($_.Exception.Message)" -Color Red
                        $accessFailures += [PSCustomObject]@{
                            SubscriptionName = $sub.Name
                            ResourceType     = "Microsoft.Compute/virtualMachines"
                            ResourceName     = $resource.Name
                            Operation        = "Get-AzVM"
                            Error            = $_.Exception.Message
                        }
                        continue
                    }

                    if ($powerState -eq "PowerState/deallocated") {
                        PrintMessage -M "VM $($vm.Name) is Stopped (deallocated) status, skipping" -Color Red
                        continue
                    }

                    $nic = Get-AzNetworkInterface -ResourceId $vm.NetworkProfile.NetworkInterfaces[0].Id

                    $publicIp = if ($nic.IpConfigurations.PublicIpAddress) {
                        Get-AzPublicIpAddress -Name $nic.Name
                    }

                    $privateIp = $nic.IpConfigurations.PrivateIpAddress

                    # ---------- Query AD (only if we actually have an IP) ----------
                    if ($privateIp) {
                        $fqdn = Get-ADComputer `
                                -Filter {Name -eq $vm.Name} `
                                -SearchScope Subtree `
                                -Server $privateIp `
                                -ErrorAction SilentlyContinue |
                                Select-Object -ExpandProperty DNSHostName -First 1
                    } else {
                        $fqdn = $null   # we could not resolve the SRV record at all
                    }

                    # ---------- Continue ----------
                    if (-not $fqdn) {
                        PrintMessage -M "Could not find FQDN of the machine" -Color Red
                        PrintMessage -M "Trying to resolve via DNS" -Color Yellow

                        try {
                            $resolved = Resolve-DnsName -Name $vm.Name -ErrorAction Stop
                            $fqdn = $resolved.Name
                            PrintMessage -M "$($fqdn) resolves to $($resolved.IPAddress[0])" -Color Green
                        } catch {
                            PrintMessage -M "Could not resolve FQDN" -Color Red
                            $azureVMsNoDns += [PSCustomObject]@{
                                VMName        = $vm.Name
                                ResourceGroup = $vm.ResourceGroupName
                                FQDN          = $fqdn
                                Error         = $_.Exception.Message
                            }
                        }
                    }

                    if (-not $fqdn) {
                        PrintMessage -M "FQDN is still unresolved, trying to fallback to private IP" -Color Yellow
                        if ($privateIp) {
                            $fqdn = $privateIp
                        } else {
                            PrintMessage -M "Wanted to fallback to a private IP but private IP is also not found $($nic.IpConfigurations)" -Color Red
                        }
                        PrintMessage -M "Falling back to private IP ($($privateIp)) for $($vm.Name)" -Color Yellow
                    }

                    # Check the OS type
                    if ($vm.StorageProfile.OsDisk.OsType -eq 'Windows') {
                        # First check if VM is ready to answer on WinRM
                        $winrmReady = $false
                        try {
                            Test-WSMan -ComputerName $fqdn -ErrorAction Stop | Out-Null
                            $winrmReady = $true
                            PrintMessage -M "$fqdn Test-WSMan succeeded"
                        } catch {
                            $winrmReady = $false
                            Printmessage -M "$fqdn Test-WSMan failed" -Color Red
                            $azureVMsWithWinRMError += [PSCustomObject]@{
                                VM               = $vm.Name
                                ResourceGroup    = $vm.ResourceGroupName
                                Error            = $_.Exception.Message
                            }
                            PrintMessage -M "WinRM failed" -Color Red
                            PrintMessage -M $_.Exception.Message -Color Red
                            continue
                        }
                        try {
                            PrintMessage -M "Attempting to connect via WinRM on $fqdn"
                            
                            # Fetch certificates from the remote VM
                            PrintMessage -M "Trying the WinRM against uefa.local"
                            $certs = Invoke-Command { Get-ChildItem cert:\LocalMachine\My -Recurse} -ComputerName $fqdn | Select-Object Thumbprint, Subject, NotAfter, NotBefore, Issuer
                        } catch {
                            Printmessage -M "$fqdn WinRM failed" -Color Red
                            $azureVMsWithWinRMError += [PSCustomObject]@{
                                VM               = $vm.Name
                                ResourceGroup    = $vm.ResourceGroupName
                                Error            = $_.Exception.Message
                            }
                            PrintMessage -M "WinRM failed" -Color Red
                            PrintMessage -M $_.Exception.Message -Color Red
                            continue
                        }
                            
                            
                        if ($certs.Count -eq 0) {
                            PrintMessage -M "No certificates found"
                            continue
                        } else {
                            PrintMessage -M "Found $($certs.Count) certificates" -Color Green
                        }
                            
                        PrintMessage -M "Checking for certificates"

                        if ($certificates.Count -eq 0) {
                            PrintMessage -M "No certificates found on the machine"
                        } else {
                            PrintMessage -M "Found certificates" -Color Green

                            foreach ($cert in $certificates) {
                                # Correctly parse the expiry date
                                $expiry = [DateTime]$cert.NotAfter
                                
                                # Calculate days until expiry
                                $daysUntilExpiry = ($expiry - (Get-Date)).Days
                                
                                # Include expired certificates and those expiring within the set threshold
                                if ($daysUntilExpiry -le $expiryCheckInDays) {
                                    PrintMessage -M "Found a certificate that expires within the set deadline - Issuer: $($cert.Issuer), Subject: $($cert.Subject), Thumbprint: $($cert.Thumbprint), Expiry: $expiry" -Color Red

                                    # Add certificate to the array with proper DateTime comparison
                                    $azureVMCertificates += [PSCustomObject]@{
                                        VM               = $vm.Name
                                        ResourceGroup    = $vm.ResourceGroupName
                                        Issuer           = $cert.Issuer
                                        Subject          = $cert.Subject
                                        Expires          = $expiry
                                        DaysUntilExpired = $daysUntilExpiry
                                        Thumbprint       = $cert.Thumbprint
                                    }
                                }
                            }
                        }
                        
                    } else {
                        PrintMessage -M "Running Linux. Not implemented yet." -Color Red
                    }
                    PrintMessage -M "============================================================================"
                }
            } # Closing the switch statement
        } # Close the foreahc for $resource in $resources

        # Web apps separate from the main loop as there we want to loop over resource groups and not each web app individually, which will make unnecessary calls
        if ($resourceType -eq "Microsoft.Web/sites") {
            $resources = Get-AzResource -ResourceType "Microsoft.Web/sites"
            PrintMessage -M "Checking resource group $($resource.Name) for web apps certificates" -Color Magenta
            $webAppResourceGroups = $resources | Select-Object -ExpandProperty ResourceGroupName -Unique # Get the names of the resource groups
            # Loop over each resource group that has web apps in it
            foreach ($resourceGroup in $webAppResourceGroups) {
                try {
                    $certs = Get-AzWebAppCertificate -ResourceGroupName $resourceGroup -ErrorAction Stop
                } catch {
                    PrintMessage -M "Failed to get Web App certificates for resource group '$($resourceGroup)': $($_.Exception.Message)" -Color Red
                    $accessFailures += [PSCustomObject]@{
                        SubscriptionName = $sub.Name
                        ResourceType     = "Microsoft.Web/sites"
                        ResourceName     = $resourceGroup
                        Operation        = "Get-AzWebAppCertificate"
                        Error            = $_.Exception.Message
                    }
                    continue
                }
                if ($certs.Count -gt 0) {
                    foreach ($cert in $certs) {
                        if ($cert.expirationDate -le (Get-Date).AddDays($expiryCheckInDays)) {
                            PrintMessage -M "Found Web App certificate that expires within the set deadline in $($resourceGroup). Certificate: $($cert.Name) | Expiration : $($cert.expirationDate) | Thumbprint $($cert.Thumbprint)" -Color Red
                            $webAppCertificates += [PSCustomObject]@{
                                SubscriptionName = $sub.Name
                                VaultName        = $resourceGroup
                                Name             = $cert.name
                                Expires          = $cert.expirationDate
                                DaysUntilExpired = ($cert.expirationDate - (Get-Date)).Days
                                Thumbprint       = $cert.thumbprint
                            }
                        }
                    }
                }
                # Let's go through the web apps and check their bindings, see if any binding points to a non-existing certificate, because we've had this case before and we want to find it
                PrintMessage -M "Checking web app SSL bindings" -Color Yellow
                $webAppsInResourceGroup = Get-AzWebApp -ResourceGroupName $resourceGroup
                foreach ($webapp in $webAppsInResourceGroup) {
                    PrintMessage -M "Checking SSL bindings for web app: $($webapp.Name) in resource group: $($resourceGroup)" -Color Yellow
                    $bindings = Get-AzWebAppSSLBinding -ResourceGroupName $resourceGroup -WebAppName $webapp.Name
                    if ($bindings.Count -gt 0) {
                        foreach ($binding in $bindings) {
                            if ($binding.SslState -eq "SniEnabled" -or $binding.SslState -eq "IpBasedEnabled") {
                                if ($binding.Thumbprint) {
                                    $foundCert = $certs | Where-Object { $_.Thumbprint -eq $binding.Thumbprint } # this would be certs in the same resource group (web apps cannot bind to certificates outside of their resource group)
                                    if (-not $foundCert) {
                                        PrintMessage -M "Web app binding with non-existent certificate thumbprint found in $($resourceGroup)/$($webApp.Name). Binding: $($binding.Name) | Thumbprint: $($binding.Thumbprint)" -Color Red
                                        $webAppsWithMissingCertificates += [PSCustomObject]@{
                                            WebAppName = $webApp.Name
                                            ResourceGroup = $resourceGroup
                                            hostname = $binding.Name
                                            thumbprint = $binding.Thumbprint
                                            BindingStatus = "nonExistentCertificate"
                                        }
                                    }
                                } else {
                                    PrintMessage -M "Binding for $($binding.Name) has no thumbprint. Investigate"
                                }
                            } else {
                                PrintMessage -M "Binding for $($binding.Name) found but SslState is not SniEnabled or IpBasedEnabled" -Color Red
                            }
                        }
                    } else {
                        PrintMessage -M "No SSL bindings found for web app: $($webapp.Name) in resource group: $($webapp.ResourceGroupName)" -Color Yellow
                    }
                }
            }
        } # Close the web apps if
    } # Close the foreach for resources in resourceTypes
} # Close the foreach for $sub in $subscriptionsToProcess


# =============================================== DATA PREPARATION ===================================================
$certificateMappings = @{
    "Microsoft.KeyVault/vaults"                             = @{ Title = "Key Vault Certificates"; Var = $keyVaultCertificates }
    "Microsoft.KeyVault/vaults-secrets"                     = @{ Title = "Key Vault Secrets"; Var = $keyVaultSecrets }
    "Microsoft.CertificateRegistration/certificateOrders"   = @{ Title = "App Service Certificates"; Var = $AppServiceCertificates }
    "Microsoft.Web/sites"                                   = @{ Title = "Web App Certificates"; Var = $webAppCertificates }
    "Microsoft.Network/applicationGateways"                 = @{ Title = "Application Gateway Certificates"; Var = $appGatewayCertificates }
    "Microsoft.Cdn/profiles"                                = @{ Title = "Front Door CDN Secrets"; Var = $frontDoorSecrets }
    "Microsoft.ApiManagement/service"                       = @{ Title = "APIM Certificates"; Var = $apimCetificates }
    "Microsoft.App/managedEnvironments"                     = @{ Title = "Container App Environment Certificates"; Var = $containerEnvironmentCertificates }
    "Microsoft.HybridCompute/machines"                      = @{ Title = "Azure Arc VM Certificates"; Var = $azureArcVMCertificates }
    "Microsoft.Compute/virtualMachines"                     = @{ Title = "Azure VM Certificates"; Var = $azureVMCertificates}
}

# Iterate through each resource type and generate HTML dynamically saving to the $html variable, which will be used in both email and html report generation
foreach ($resourceType in $resourceTypes) {
    if ($certificateMappings.ContainsKey($resourceType)) {
        $title = $certificateMappings[$resourceType].Title
        $certificates = $certificateMappings[$resourceType].Var

        $html += "<h1>$title</h1>"
        if ($certificates.Count -eq 0) {
            $html += "<p>No $title found that are expiring in the next $expiryCheckInDays days.</p>"
        } else {
            $html += ConvertTo-HtmlTable -Certificates $certificates
        }
    }
}

# Combine all the arrays into one so we can distill the unique certificates

# Initialize combined certificates array
$combinedCertificates = @()

# Iterate over certificate mappings and add all certificates dynamically
foreach ($entry in $certificateMappings.Values) {
    $combinedCertificates += $entry.Var
}

# Remove duplicates based on the Thumbprint property so we can actually see what certificates need renewing, because the same certificate can be used in many resource types
$uniqueCertificates = $combinedCertificates | Group-Object -Property Thumbprint | ForEach-Object { $_.Group[0] }

# Now reduce the keys of the unique certificates to only the ones we need - Name, Expires, DaysUntilExpired, Thumbprint
$uniqueCertificates = $uniqueCertificates | Select-Object Name, Expires, DaysUntilExpired, Thumbprint

$uniqueCertificatesHtml = ''

if ($uniqueCertificates.Count -eq 0) {
    $uniqueCertificatesHtml += "<p>No certificates found that are expiring in the next $expiryCheckInDays days.</p>"
} else {
    $uniqueCertificatesHtml += ConvertTo-HtmlTable -Certificates $uniqueCertificates
}

$missingCertificatesinWebAppBindingsHtml = ''

if ($webAppsWithMissingCertificates.Count -eq 0) {
    $missingCertificatesinWebAppBindingsHtml += "<p>No bindings found that point to missing certificates. All good</p>"
} else {
    $missingCertificatesinWebAppBindingsHtml += ConvertTo-HtmlTable -Certificates $webAppsWithMissingCertificates
}

$azureVMsWithErrorsHtml = ''

if ($azureVMsWithWinRMError.Count -eq 0 -and $certificateMappings.ContainsKey("Microsoft.Compute/virtualMachines")) {
    $azureVMsWithErrorsHtml += '<p style="color: green">No Azure VMs with WinRM errors</p>'
} else {
    foreach ($vm in $azureVMsWithWinRMError) {
        $azureVMsWithErrorsHtml += "<p>$($vm.VM) | $($vm.ResourceGroup)</p>"
        $azureVMsWithErrorsHtml += "<p style='color: red'>$($vm.Error)</p>"
    }
}

$azureVMsNoDnsHtml = ''

if ($azureVMsNoDns.Count -eq 0 -and $certificateMappings.ContainsKey("Microsoft.Compute/virtualMachines")) {
    $azureVMsNoDnsHtml += '<p style="color: green">No Azure VMs with DNS errors</p>'
} else {
    $azureVMsNoDnsHtml += ConvertTo-HtmlTable -Certificates $azureVMsNoDns
}

$accessFailuresHtml = ''

if ($accessFailures.Count -eq 0) {
    $accessFailuresHtml += '<p style="color: green">No access failures encountered. All resources were accessible.</p>'
} else {
    $accessFailuresHtml += ConvertTo-HtmlTable -Certificates $accessFailures
}

# ======================================================================== HTML ========================================================================
$logoPath = "https://th.bing.com/th?id=OSK._VzmtCTcZJJkebzQTlfAW7BJ2ed6QuH_V1gc2TFDnvo&w=102&h=102&c=7&o=6&dpr=1.3&pid=SANGAM" # Needs to be publicly accessible

$whereItRuns = 'This is an automated report that ran locally'

if ($runInAutomation) {
    $whereItRuns = "This is an automated report running in Azure Automation Account"
}

if ($runInBastion) {
    $whereItRuns = "This ia an automated report running on Azure DevOps Bastion"
}

# Html for Automation Account
$finalHtml = @"
     <p>Setting: expiry less than <b>$expiryCheckInDays</b> days</p>
        <p>Resource types checked:</p>
        <ul>
            $($resourceTypes | ForEach-Object { "<li>$_</li>" })
        </ul>
        <p>Subscriptions checked:</p>
        <ul>
            $($subscriptionsToProcess | ForEach-Object { "<li>$($_.Name)</li>" })
        </ul>
        $html
        <h1>Access Failures</h1>
        <p>Resources that could not be accessed due to permission issues.</p>
        $accessFailuresHtml
        <hr />
        <h1>Azure VMs with WinRM Errors</h1>
        $azureVMsWithErrorsHtml
        <hr />
        <h1>Azure VMs with DNS Errors</h1>
        $azureVMsNoDnsHtml
        <hr />
        <h1>Broken Web App Bindings</h1>
        <p>We've had cases where the certificates behind bindings are gone so the bindings are in good shape but the certificate that they point to is no longer there. This causes everything to be green but also the web app will throw errors. So here is the result of the hunt for these rogue bindings.</p>
        $missingCertificatesinWebAppBindingsHtml
        <hr />
        <h1>Summary - Certificates to renew</h1>
        <p><b>Because the same certificate can be used in many resource types, here is a distilled list of the actual certficiates that needs renewing.</b></p>
        $uniqueCertificatesHtml
        <hr />
"@

# Html for the html report (suitable for being sent over an email but not through the Automation account since it adds headers and footers on its own)
$MsgBody = @"
<!DOCTYPE>
<html lang="EN-US">
<head>
    <style>
        h1 {
            mso-style-priority: 9;
            mso-style-link: 'Heading 1 Char';
            margin: 0cm 0cm 8.0pt 0cm;
            line-height: 24.0pt;
            font-size: 14.0pt;
            font-family: 'Arial', sans-serif;
            color: $htmlFontColor;
            font-weight: bold;
        }
        h2 {
            mso-style-priority: 9;
            mso-style-link: 'Heading 2 Char';
            margin: 0cm 18.75pt 8.0pt 0cm;
            line-height: 10.0pt;
            font-size: 8.0pt;
            font-family: 'Arial', sans-serif;
            color: $htmlFontColor;
            font-weight: bold;
        }
        @page WordSection1 {
            size: 612.0pt 792.0pt;
            margin: 70.85pt;
        }
        div.WordSection1 {
            page: WordSection1;
        }
    </style>
    <meta http-equiv="Content-Type" content="text/html; charset=us-ascii">
    <title>Azure Expired Certificates</title>
</head>
<body bgcolor="#E4E4E4" lang="EN-US" link="$htmlFontColor" vlink="$htmlFontColor">
    <div align="center" class="WordSection1">
        <table class="MsoNormalTable" border="0" cellspacing="0" cellpadding="0" width="0" style="width:850px; background:white;">
            <tr>
                <!-- This is the blue line on the left -->
                <td width="3%" valign="top" style="background:#00338D; padding:0;">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td> <!-- we need this &nbsp; to make the cell visible and width is as many of these as we want-->
                <! -- Logo and title and then the rest of the html -->
                <td width="97%" style="padding:0;">
                    <table border="0" cellspacing="0" cellpadding="0" width="100%" style="width:100%; background:white">
                        <tr>
                            <td style="padding:1cm;">
                                <h1>Azure SSL Cerificates Expiry Report</h1>
                                <h1>Date: $(Get-Date -Format 'dd MMMM yyyy')</h1>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <div style="margin:10px">
                                    <p>Setting: expiry less than <b>$expiryCheckInDays</b> days</p>
                                    <p>Resource types checked:</p>
                                    <ul>
                                        $($resourceTypes | ForEach-Object { "<li>$_</li>" })
                                    </ul>
                                    <p>Subscriptions checked:</p>
                                    <ul>
                                        $($subscriptionsToProcess | ForEach-Object { "<li>$($_.Name)</li>" })
                                    </ul>
                                    $html
                                    <hr />
                                    <h1>Access Failures</h1>
                                    <p>Resources that could not be accessed due to permission issues.</p>
                                    $accessFailuresHtml
                                    <hr />
                                    <h1>Azure VMs with WinRM Errors</h1>
                                    $azureVMsWithErrorsHtml
                                    <hr />
                                    <h1>Azure VMs with DNS Errors</h1>
                                    $azureVMsNoDnsHtml
                                    <hr />
                                    <h1>Broken Web App Bindings</h1>
                                    <p>We've had cases where the certificates behind bindings are gone so the bindings are in good shape but the certificate that they point to is no longer there. This causes everything to be green but also the web app will throw errors. So here is the result of the hunt for these rogue bindings.</p>
                                    $missingCertificatesinWebAppBindingsHtml
                                    <hr />
                                    <h1>Summary - Certificates to renew</h1>
                                    <p><b>Because the same certificate can be used in many resource types, here is a distilled list of the actual certficiates that needs renewing.</b></p>
                                    $uniqueCertificatesHtml
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <div style="margin:10px">
                                    <p style='font-family:&quot;Arial&quot;,sans-serif;color:#747678;text-decoration:none;font-size:7.5pt'>$whereItRuns<o:p></o:p></p>
                                    <p style='font-family:&quot;Arial&quot;,sans-serif;color:#747678;text-decoration:none;font-size:7.5pt'>INTERNAL USE ONLY<o:p></o:p></p>
                                    <!-- END footnote -->
                                </div>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </div>
</body>
</html>
"@
# =============================================== HTML REPORT FOR LOCAL AND STORAGE ACCOUNT ===============================================
if ($PSScriptRoot) {
    Set-Location -Path $PSScriptRoot
    $currentLocation = Get-Location  # Capture the new location after setting it
} else {
    PrintMessage -M "Seems to be running Interactively, setting the current location to the script location" -Color Yellow
    $currentLocation = Get-Location
}

# Prepare the report file name
$reportName = "Report-$(Get-Date -Format 'dd-MM-yyyy').html"

if ($saveReportLocally) {
    # Combine the current location with the report name to get the full path
    $fullReportPath = Join-Path -Path $currentLocation.Path -ChildPath $reportName

    # Write the report to a file
    $MsgBody | Out-File -FilePath $fullReportPath

    # Print the local location of the report
    PrintMessage -M "Report saved to: $fullReportPath. Open in browser via file://$($fullReportPath.Replace('\', '/'))" -Color Green
}

if ($saveReportToStorage) {
    PrintMessage -M "Now proceeding to upload the report to the storage account" -Color Yellow

    # Create storage context using the connected account
    $storageContext = New-AzStorageContext -StorageAccountName $storageAccountName -UseConnectedAccount

    # Check if the blob already exists
    $existingBlob = Get-AzStorageBlob -Container $containerName -Blob $reportName -Context $storageContext -ErrorAction SilentlyContinue

    if ($existingBlob) {
    PrintMessage -M "A report with the name $reportName already exists. Deleting and uploading the new one." -Color Red

    # Delete the existing blob
    Remove-AzStorageBlob -Container $containerName -Blob $reportName -Context $storageContext
    }

    try {
        Set-AzStorageBlobContent -Container $containerName -Blob $reportName -Context $storageContext -File $reportName -Properties @{"ContentType" = "text/html"}

        PrintMessage -M "Report uploaded to storage account: $storageAccountName in container: $containerName with name: $reportName" -Color Green
    } catch {
        PrintMessage -M "Failed to upload report to storage account: $storageAccountName in container: $containerName with name: $reportName" -Color Red
        PrintMessage -M $_.Exception.Message -Color Red
    }
}
# ========================================================== EMAIL REPORT =======================================================

# ======================================================== OUTPUT LOG ========================================================
# Output the log collected in $log
if ($saveOutputToFile) {
    $log | Out-File -FilePath "$($currentLocation.Path)\Azure-SSL-Expiration-Report-Ouput-Log-$(Get-Date -Format 'dd-MM-yyyy').log"
    PrintMessage -M "Log saved to: $($currentLocation.Path)\Azure-SSL-Expiration-Report-Ouput-Log-$(Get-Date -Format 'dd-MM-yyyy').log" -Color Green
}