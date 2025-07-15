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