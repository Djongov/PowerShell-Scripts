<# ============ Initial setup, need to run only once ==============#>
#Install-Module -Name Posh-ACME -Scope AllUsers
#Import-Module Posh-ACME
#Update-Module -Name Posh-ACME
#Set-PAServer LE_PROD
#New-PAAccount -Contact 'mailto:djongov@gamerz-bg.com' -AcceptTOS
<#
d                   status          contact                                                                                                                                                                                                alg        KeyLength 
--                   ------          -------                                                                                                                                                                                                ---        --------- 
2243461895           valid           {mailto:djongov@gamerz-bg.com} 
#>
#<# ============ First certificate issuance, need to run only once per certificate ==============#>
# $certNames = '*.sunwellsolutions.com', 'sunwellsolutions.com'
# $email = 'djongov@gamerz-bg.com'
# New-PACertificate $certNames -AcceptTOS -Contact $email
# #Output is in %LOCALAPPDATA%\Posh-ACME. There should a folder in there and there should be one or two subfolders. 
# #You will find actual .cer files in one of them. You can directly use .pfx - password is poshacme
# #https://github.com/rmbolger/Posh-ACME
# Invoke-Item $env:USERPROFILE\AppData\Local\Posh-ACME\LE_PROD\2617473177
<# ============ Renewal ==============#>
Submit-Renewal -MainDomain '*.sunwellsolutions.com' -NoSkipManualDns
Invoke-Item $env:USERPROFILE\AppData\Local\Posh-ACME\LE_PROD\2617473177