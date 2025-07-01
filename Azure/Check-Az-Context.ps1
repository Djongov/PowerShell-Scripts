$context = Get-AzContext

if ($null -eq $context) {
    # Not authenticated, call Connect-AzAccount
    Write-Host "Not authenticated, please sign in."
    Connect-AzAccount
} else {
    # Authenticated, ask if user wants to continue with the current account
    Write-Host "You are authenticated as:" $context.Account
    $response = $null
    
    while ($response -ne 'Y' -and $response -ne 'y' -and $response -ne 'N' -and $response -ne 'n') {
        $response = Read-Host "Do you want to continue with this account? (Y/N)"
    }

    if ($response -eq 'Y' -or $response -eq 'y') {
        Write-Host "Continuing with current account..."
    } else {
        # Call Connect-AzAccount for a new authentication
        Write-Host "Re-authenticating..."
        Connect-AzAccount
    }
}