. "$(Join-Path -Path $PSScriptRoot -ChildPath '../Check-Az-Context.ps1')"

# Because we run a lot of az cli commands, we need to ensure the Azure CLI is logged in the same account as the current Azure PowerShell context.
$azAccount = (az account show --query user.name -o tsv)

if ($azAccount -eq $context.Account) {
    Write-Host "Azure CLI account matches context account." -ForegroundColor Green
} else {
    Write-Host "Azure CLI account DOES NOT match context account." -ForegroundColor Red
    az logout
    Write-Host "Logging out of Azure CLI..."
    az login
    az account set --subscription $context.Subscription.Id
    Write-Host "Azure CLI account set to match context account: $($context.Account)"
}


# Set the registry name
$acrName = Read-Host "Enter the Azure Container Registry name"
$acrSubscription = Read-Host "Enter the Azure subscription name (optional, press Enter to skip)"

# If a subscription name is provided, set the context to that subscription
if (-not [string]::IsNullOrEmpty($acrSubscription)) {
    $subscription = Get-AzSubscription -SubscriptionName $acrSubscription
    if ($null -eq $subscription) {
        Write-Host "Subscription '$acrSubscription' not found. Please check the name and try again."
        exit 1
    }
    Set-AzContext -SubscriptionId $subscription.Id
}

# Get all repositories
$repositories = az acr repository list --name $acrName --output json | ConvertFrom-Json

$result = @()

foreach ($repo in $repositories) {
    Write-Host "Processing repository: $repo"

    # Get tags
    $tags = az acr repository show-tags --name $acrName --repository $repo --output json | ConvertFrom-Json
    $tagCount = $tags.Count

    # Get image manifests (digests) with new correct syntax
    $manifestsJson = az acr manifest list-metadata --registry $acrName --name $repo --output json 2>$null
    $manifests = $manifestsJson | ConvertFrom-Json

    $manifestsCount = $manifests.Count

    $result += [PSCustomObject]@{
        Repository     = $repo
        TagCount       = $tagCount
        manifestsCount = $manifestsCount
    }
}

# Output to table
$result | Sort-Object TagCount -Descending | Format-Table -AutoSize

# Get current date and time in format yyyyMMdd_HHmm
$timestamp = Get-Date -Format "yyyyMMdd_HHmm"

$fileName = "acr_repositories_report_$timestamp.csv"

# Define output CSV path in user profile root
$outputPath = Join-Path -Path $env:USERPROFILE -ChildPath $fileName

# Export result to CSV
$result | Sort-Object TagCount -Descending | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

Write-Host "Report saved to $outputPath"