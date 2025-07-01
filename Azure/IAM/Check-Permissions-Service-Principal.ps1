. "$(Join-Path -Path $PSScriptRoot -ChildPath '../Check-Az-Context.ps1')"

$spId = Read-Host "Enter the Service Principal ID (App ID) to check permissions"
$logFile = Join-Path -Path $env:USERPROFILE -ChildPath "SP-Permissions-Check.log"

$skipSubscriptions = @("UEFA_Corporate_nonPRD", "UEFA_AMFUnit", "D3 - Service Bus Development", "D3 - Service Bus Production", "Pago por uso", "UEFA_Corporate_PRD", "UEFA_DNS Azure") 

# Clear log file if exists
if (Test-Path $logFile) { Remove-Item $logFile -Force }

$allHits = @()

$subscriptions = Get-AzSubscription

foreach ($sub in $subscriptions) {
    if ($skipSubscriptions -contains $sub.Name -or $skipSubscriptions -contains $sub.Id) {
        Write-Host "Skipping Subscription: $($sub.Name) ($($sub.Id))" -ForegroundColor Yellow
        Add-Content -Path $logFile -Value "Skipping Subscription: $($sub.Name) ($($sub.Id))"
        continue
    }
    Write-Host "======================================================================="
    Write-Host "Checking Subscription: $($sub.Name)" -ForegroundColor Cyan
    Add-Content -Path $logFile -Value "======================================================================="
    Add-Content -Path $logFile -Value "Checking Subscription: $($sub.Name)"

    Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop

    # Get role assignments for the SP at subscription scope
    $subRoles = Get-AzRoleAssignment -ObjectId $spId -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue
    if ($subRoles) {
        Write-Host "`nRole Assignments at Subscription scope:"
        Add-Content -Path $logFile -Value "`nRole Assignments at Subscription scope:"
        foreach ($role in $subRoles) {
            Write-Host "  Role: $($role.RoleDefinitionName)"
            Add-Content -Path $logFile -Value "  Role: $($role.RoleDefinitionName)"
            $allHits += $role
        }
    }

    # Get all resource groups
    $resourceGroups = Get-AzResourceGroup
    foreach ($rg in $resourceGroups) {
        $rgScope = "/subscriptions/$($sub.Id)/resourceGroups/$($rg.ResourceGroupName)"

        # Get role assignments at resource group scope
        $rgRoles = Get-AzRoleAssignment -ObjectId $spId -Scope $rgScope -ErrorAction SilentlyContinue
        if ($rgRoles) {
            Write-Host "`nResource Group: $($rg.ResourceGroupName) - Roles:"
            Add-Content -Path $logFile -Value "`nResource Group: $($rg.ResourceGroupName) - Roles:"
            foreach ($role in $rgRoles) {
                Write-Host "  Role: $($role.RoleDefinitionName)"
                Add-Content -Path $logFile -Value "  Role: $($role.RoleDefinitionName)"
                $allHits += $role
            }
        }
    }

    # Get all resources
    $resources = Get-AzResource
    foreach ($res in $resources) {
        $resScope = $res.ResourceId

        $resRoles = Get-AzRoleAssignment -ObjectId $spId -Scope $resScope -ErrorAction SilentlyContinue
        if ($resRoles) {
            Write-Host "`nResource: $($res.Name) ($($res.Type)) - Roles:"
            Add-Content -Path $logFile -Value "`nResource: $($res.Name) ($($res.Type)) - Roles:"
            foreach ($role in $resRoles) {
                Write-Host "  Role: $($role.RoleDefinitionName)"
                Add-Content -Path $logFile -Value "  Role: $($role.RoleDefinitionName)"
                $allHits += $role
            }
        }
    }
    Write-Host "======================================================================="
    Add-Content -Path $logFile -Value "======================================================================="
}

# Output summary
Write-Host "`nSummary: Found $($allHits.Count) role assignments for Service Principal $spId"
Add-Content -Path $logFile -Value "`nSummary: Found $($allHits.Count) role assignments for Service Principal $spId"
