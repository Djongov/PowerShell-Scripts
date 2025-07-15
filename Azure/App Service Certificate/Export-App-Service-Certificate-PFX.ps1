# Self-elevate if not running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
            [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Not running as Administrator. Relaunching with elevation..."
    Start-Process -FilePath "powershell" -Verb RunAs -ArgumentList "-NoExit", "-File", "`"$PSCommandPath`""
    exit
}

. "$(Join-Path -Path $PSScriptRoot -ChildPath '../Check-Az-Context.ps1')"

$appServiceCertificateName = Read-Host "Enter the App Service Certificate name"
$resourceGroupName = Read-Host "Enter the resource group name of the App Service Certificate"
$subscriptionId = Read-Host "Enter the subscription ID (optional, press Enter to skip)"

#Login-AzAccount;
Set-AzContext -SubscriptionId $subscriptionId

$ascResource = Get-AzResource -ResourceName $appServiceCertificateName -ResourceGroupName $resourceGroupName -ResourceType "Microsoft.CertificateRegistration/certificateOrders" -ApiVersion "2015-08-01"
$keyVaultId = ""
$keyVaultSecretName = ""

$certificateProperties = Get-Member -InputObject $ascResource.Properties.certificates[0] -MemberType NoteProperty
$certificateName = $certificateProperties[0].Name
$keyVaultId = $ascResource.Properties.certificates[0].$certificateName.KeyVaultId
$keyVaultSecretName = $ascResource.Properties.certificates[0].$certificateName.KeyVaultSecretName

$keyVaultIdParts = $keyVaultId.Split("/")
$keyVaultName = $keyVaultIdParts[$keyVaultIdParts.Length - 1]
#$keyVaultResourceGroupName = $keyVaultIdParts[$keyVaultIdParts.Length - 5]
#Set-AzKeyVaultAccessPolicy -ResourceGroupName $keyVaultResourceGroupName -VaultName $keyVaultName -UserPrincipalName $azureLoginEmailId -PermissionsToSecrets get
# Attempt to get the secret from Key Vault, but let's use try because there might be insufficient permissions
try {
    $secret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $keyVaultSecretName
} catch {
    Write-Error $_.Exception.Message -ForegroundColor Red
    exit 1
}

$ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue)
$secretValueText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)

$pfxCertObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @([Convert]::FromBase64String($secretValueText), "", [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
$pfxPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 50 | % { [char]$_ })

# Construct an absolute path
$pfxFilePath = Join-Path -Path $env:USERPROFILE -ChildPath "$appServiceCertificateName.pfx"

# Write the PFX file using an absolute path
[io.file]::WriteAllBytes($pfxFilePath, $pfxCertObject.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $pfxPassword))

Write-Host "Created an App Service Certificate copy at: $pfxFilePath"
Write-Warning "For security reasons, do not store the PFX password. Use it directly from the console as required."
Write-Host "PFX password: $pfxPassword"

# Open the user profile directory
Invoke-Item $env:USERPROFILE