. "$(Join-Path -Path $PSScriptRoot -ChildPath '../Check-Az-Context.ps1')"

# Collect empty App Service Plans
$emptyPlans = @()

# Get all tenants
$tenants = Get-AzTenant

# Loop through each tenant
foreach ($tenant in $tenants) {
    Write-Host "Processing Tenant: $($tenant.TenantId)" -ForegroundColor Cyan

    # Set current tenant context
    Set-AzContext -TenantId $tenant.TenantId | Out-Null

    # Get all subscriptions for the current tenant
    $azureSubs = Get-AzSubscription | Where-Object { $_.TenantId -eq $tenant.TenantId }

    foreach ($sub in $azureSubs) {
        Select-AzSubscription -SubscriptionId $sub.Id | Out-Null
        Write-Host "Checking subscription: $($sub.Name)" -ForegroundColor Yellow

        try {
            $originalProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'

            Write-Host "Retrieving App Service Plans in subscription $($sub.Name)..." -ForegroundColor Green

            $plans = Get-AzAppServicePlan -ErrorAction Stop | Where-Object {
                $_.NumberOfSites -eq 0 -and $_.Sku.Name -notin @('F1', 'Y1')
            }

            foreach ($plan in $plans) {
                $emptyPlans += [PSCustomObject]@{
                    TenantId         = $tenant.TenantId
                    SubscriptionId   = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $plan.ResourceGroup
                    PlanName         = $plan.Name
                    Location         = $plan.Location
                    Sku              = $plan.Sku.Name
                }
            }
        } catch {
            Write-Warning "Failed to get plans for subscription $($sub.Name): $_"
        } finally {
            $ProgressPreference = $originalProgressPreference
        }
    }
}

# Show summary
if ($emptyPlans.Count -eq 0) {
    Write-Host "No empty App Service Plans found." -ForegroundColor Green
    return
}

Write-Host "`nFound $($emptyPlans.Count) empty App Service Plans:`n" -ForegroundColor Cyan
$emptyPlans | Format-Table -AutoSize

# Ask user for confirmation to delete
$confirm = Read-Host "`nDo you want to delete these plans? (y/n)"
if ($confirm -eq 'y') {
    foreach ($plan in $emptyPlans) {
        Write-Host "Deleting plan $($plan.PlanName) in subscription $($plan.SubscriptionName)" -ForegroundColor Red
        Select-AzSubscription -SubscriptionId $plan.SubscriptionId | Out-Null

        try {
            Remove-AzAppServicePlan -ResourceGroupName $plan.ResourceGroup -Name $plan.PlanName -Force -ErrorAction Stop
            Write-Host "`tDeleted $($plan.PlanName)" -ForegroundColor Green
        } catch {
            Write-Warning "`tFailed to delete $($plan.PlanName): $_"
        }
    }
} else {
    Write-Host "No plans were deleted." -ForegroundColor Yellow
}
