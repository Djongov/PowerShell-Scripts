$url = "https://azure-waf-manager-api.sunwellsolutions.com/v1/ip"

$method = "GET"

$headers = @{}

#$headers.Add("Authorization", "Bearer <your_access_token_here>")

try {
    $response = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop -Verbose -MaximumRedirection 0 -MaximumRetryCount 1 -UserAgent "PowerShell/Test1.0" -OperationTimeoutSeconds 10 -ConnectionTimeoutSeconds 10
} catch {
    Write-Error "Failed to call API: $_"
    exit 1
}

$response