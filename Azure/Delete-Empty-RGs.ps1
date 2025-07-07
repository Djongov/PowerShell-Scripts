. "$(Join-Path -Path $PSScriptRoot -ChildPath 'Check-Az-Context.ps1')"

$emptyResourceGroups = @()

$tenants = Get-AzTenant

foreach ($tenant in $tenants) {
    Write-Host "Processing Tenant: $($tenant.TenantId)" -ForegroundColor Cyan
    Set-AzContext -TenantId $tenant.TenantId | Out-Null

    $azureSubs = Get-AzSubscription | Where-Object { $_.TenantId -eq $tenant.TenantId }

    foreach ($sub in $azureSubs) {
        Write-Host "`tChecking subscription: $($sub.Name)" -ForegroundColor Yellow
        Select-AzSubscription -SubscriptionId $sub.Id | Out-Null

        try {
            $resourceGroups = Get-AzResourceGroup -ErrorAction Stop
            foreach ($rg in $resourceGroups) {
                $resources = Get-AzResource -ResourceGroupName $rg.ResourceGroupName -ErrorAction Stop
                if ($resources.Count -eq 0) {
                    $emptyResourceGroups += [PSCustomObject]@{
                        TenantId         = $tenant.TenantId
                        SubscriptionId   = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup    = $rg.ResourceGroupName
                        Location         = $rg.Location
                    }
                }
            }
        } catch {
            Write-Warning "`tError processing subscription $($sub.Name): $_"
        }
    }
}

# Show summary
if ($emptyResourceGroups.Count -eq 0) {
    Write-Host "No completely empty resource groups found." -ForegroundColor Green
    return
}

Write-Host "`nFound $($emptyResourceGroups.Count) completely empty resource groups:`n" -ForegroundColor Cyan
$emptyResourceGroups | Format-Table -AutoSize

# Ask user for confirmation to delete
# Ask user per resource group whether to delete
foreach ($rg in $emptyResourceGroups) {
    Write-Host "`nFound empty RG: $($rg.ResourceGroup) in subscription: $($rg.SubscriptionName)" -ForegroundColor Cyan
    $answer = Read-Host "Do you want to delete this resource group? (y/n)"

    if ($answer -eq 'y') {
        Write-Host "Deleting RG $($rg.ResourceGroup)" -ForegroundColor Red
        Select-AzSubscription -SubscriptionId $rg.SubscriptionId | Out-Null
        try {
            Remove-AzResourceGroup -Name $rg.ResourceGroup -Force -ErrorAction Stop
            Write-Host "`tDeleted $($rg.ResourceGroup)" -ForegroundColor Green
        } catch {
            Write-Warning "`tFailed to delete $($rg.ResourceGroup): $_"
        }
    } else {
        Write-Host "`tSkipped $($rg.ResourceGroup)" -ForegroundColor Yellow
    }
}
