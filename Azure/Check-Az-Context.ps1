. "$(Join-Path -Path $PSScriptRoot -ChildPath 'Ensure-AzModule.ps1')"

$context = Get-AzContext

if ($null -eq $context) {
    # Not authenticated, call Connect-AzAccount
    Write-Host "Not authenticated, please sign in."
    Connect-AzAccount
} else {
    # Authenticated, show current context
    Write-Host "You are authenticated as:" $context.Account
    Write-Host "Current Tenant:" $context.Tenant.Id
    Write-Host "Current Subscription:" $context.Subscription.Name "($($context.Subscription.Id))"
    
    # Check for multiple tenants
    $tenants = Get-AzTenant
    if ($tenants.Count -gt 1) {
        Write-Host "`nYou have access to $($tenants.Count) tenants:"
        for ($i = 0; $i -lt $tenants.Count; $i++) {
            $isCurrent = $tenants[$i].Id -eq $context.Tenant.Id
            $marker = if ($isCurrent) { " (current)" } else { "" }
            Write-Host "  [$i] $($tenants[$i].Id)$marker"
        }
    }
    
    $response = $null
    
    while ($response -ne 'Y' -and $response -ne 'y' -and $response -ne 'N' -and $response -ne 'n' -and $response -ne 'T' -and $response -ne 't') {
        if ($tenants.Count -gt 1) {
            $response = Read-Host "`nDo you want to continue with this account? (Y/N) or switch Tenant? (T)"
        } else {
            $response = Read-Host "`nDo you want to continue with this account? (Y/N)"
        }
    }

    if ($response -eq 'Y' -or $response -eq 'y') {
        Write-Host "Continuing with current account..."
    } elseif ($response -eq 'T' -or $response -eq 't') {
        # Switch tenant
        if ($tenants.Count -gt 1) {
            $tenantIndex = Read-Host "Enter the number of the tenant you want to switch to [0-$($tenants.Count - 1)]"
            if ($tenantIndex -match '^\d+$' -and [int]$tenantIndex -ge 0 -and [int]$tenantIndex -lt $tenants.Count) {
                $selectedTenant = $tenants[[int]$tenantIndex]
                Write-Host "Switching to tenant: $($selectedTenant.Id)"
                Connect-AzAccount -Tenant $selectedTenant.Id
            } else {
                Write-Host "Invalid tenant selection. Re-authenticating..."
                Connect-AzAccount
            }
        } else {
            Write-Host "Only one tenant available. Re-authenticating..."
            Connect-AzAccount
        }
    } else {
        # Call Connect-AzAccount for a new authentication
        Write-Host "Re-authenticating..."
        Connect-AzAccount
    }
}