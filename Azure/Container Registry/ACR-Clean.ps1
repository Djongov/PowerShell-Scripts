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

$acrName = Read-Host "Enter the Azure Container Registry name"

$acrSubscription = Read-Host "Enter the Azure subscription name (optional, press Enter to skip)"

$repo = Read-Host "Enter the repository name to clean up"

$daysToKeep = Read-Host "Enter the number of days to keep images (default is 7, press Enter to skip)"

if (-not [string]::IsNullOrEmpty($daysToKeep)) {
    $daysToKeep = [int]$daysToKeep
} else {
    $daysToKeep = 7
}

# Tags to keep — all other tagged images will be deleted
$skipTags = @(
    "latest",
    "production"
)

Write-Host "=== Deleting tagged images except skip list tags and recent images (last 7 days) ==="

# Current UTC time and cutoff
$now = Get-Date -AsUTC
$cutoff = $now.AddDays(-$daysToKeep)

# Get all manifests with tags
$manifests = az acr manifest list-metadata `
    --registry $acrName `
    --name $repo `
    --output json | ConvertFrom-Json

foreach ($manifest in $manifests) {
    $tags = $manifest.tags
    $createdTime = Get-Date $manifest.createdTime

    if ($tags -and $tags.Count -gt 0) {
        $keep = $false

        # Check if it's in skip list
        foreach ($tag in $tags) {
            if ($skipTags -contains $tag) {
                $keep = $true
                break
            }
        }

        # Check if it's recent (newer than 7 days)
        if ($createdTime -gt $cutoff) {
            $keep = $true
            Write-Host "Keeping recent image (created $createdTime): $($tags -join ', ')"
        }

        if ($keep) {
            Write-Host "Skipping tags: $($tags -join ', ')"
        } else {
            foreach ($tagToDelete in $tags) {
                Write-Host "Deleting tagged image: $($repo):$tagToDelete"
                az acr repository delete `
                    --name $acrName `
                    --image "$($repo):$tagToDelete" `
                    --yes
            }
        }
    }
}

Write-Host "=== Deleting untagged manifests (older than 7 days) ==="

# Step 2: Delete only old untagged manifests
$untaggedManifests = az acr manifest list-metadata `
    --registry $acrName `
    --name $repo `
    --output json | ConvertFrom-Json | Where-Object {
    (!$_.tags -or $_.tags.Count -eq 0) -and
    (Get-Date $_.createdTime) -lt $cutoff
}

foreach ($manifest in $untaggedManifests) {
    $digest = $manifest.digest
    $created = Get-Date $manifest.createdTime
    Write-Host "Deleting untagged manifest (created $created): $digest"
    az acr repository delete `
        --name $acrName `
        --image "$($repo)@$digest" `
        --yes
}
