. "$(Join-Path -Path $PSScriptRoot -ChildPath '../Check-Az-Context.ps1')"

# Because we run a lot of az cli commands, we need to ensure the Azure CLI is logged in the same account as the current Azure PowerShell context.
. "$(Join-Path -Path $PSScriptRoot -ChildPath '../Check-Az-Cli-Az-Context.ps1')"

$acrName = Read-Host "Enter the Azure Container Registry name"

$acrSubscription = Read-Host "Enter the Azure subscription name (optional, press Enter to skip)"

if (-not [string]::IsNullOrEmpty($acrSubscription)) {
    $subscription = Get-AzSubscription -SubscriptionName $acrSubscription
    if ($null -eq $subscription) {
        Write-Host "Subscription '$acrSubscription' not found. Please check the name and try again."
        exit 1
    }
    Set-AzContext -SubscriptionId $subscription.Id
}

# Ask the user if they want to clean all or a specific repository
$cleanAll = Read-Host "Do you want to clean all repositories? (y/n)"

# Now make sure that we loop until we receive a proper response
while ($cleanAll -notin @('y', 'n')) {
    Write-Host "Invalid input. Please enter 'y' for yes or 'n' for no."
    $cleanAll = Read-Host "Do you want to clean all repositories? (y/n)"
}

if ($cleanAll -eq 'y') {
    $repo = $null
    Write-Host "=== Deleting untagged manifests for all repositories ==="
    # Step 1: Get all repositories
    $repositories = az acr repository list --name $acrName --output json | ConvertFrom-Json
    foreach ($repo in $repositories) {
        Write-Host "Processing repository: $repo"
        
        # Get untagged manifests
        $untaggedDigests = az acr manifest list-metadata --registry $acrName --name $repo --query "[?tags == null || tags == []].digest" --output tsv

        # Print the number of untagged manifests found
        if ($untaggedDigests.Count -eq 0) {
            Write-Host "No untagged manifests found for repository: $repo" -ForegroundColor Yellow
            continue
        } else {
            Write-Host "Found $($untaggedDigests.Count) untagged manifests for repository: $repo" -ForegroundColor Cyan
        }
        
        foreach ($digest in $untaggedDigests) {
            Write-Host "Deleting untagged manifest digest: $digest"
            az acr repository delete --name $acrName --image "$($repo)@$digest" --yes
        }
    }
} else {
    # Ask for the repository name to clean up
    $repo = Read-Host "Enter the repository name to clean up"
    Write-Host "=== Deleting untagged manifests for $repo ==="

    # Step 2: Delete untagged manifests
    $untaggedDigests = az acr manifest list-metadata --registry $acrName --name $repo --query "[?tags == null || tags == []].digest" --output tsv

    # Print the number of untagged manifests found
    if ($untaggedDigests.Count -eq 0) {
        Write-Host "No untagged manifests found for repository: $repo" -ForegroundColor Yellow
        return
    } else {
        Write-Host "Found $($untaggedDigests.Count) untagged manifests for repository: $repo" -ForegroundColor Cyan
    }

    foreach ($digest in $untaggedDigests) {
        Write-Host "Deleting untagged manifest digest: $digest"
        az acr repository delete --name $acrName --image "$($repo)@$digest" --yes
    }
}

