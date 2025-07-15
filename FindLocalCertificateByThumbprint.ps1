$raw_thumbprint = Read-Host 'Paste thumbprint'
$thumbprint = $raw_thumbprint.Replace(' ', '')
Get-ChildItem -path Cert:\* -Recurse | Where-Object { $_.Thumbprint -eq $thumbprint }