function CreateSelfSignedCertWithDNS {

    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
                [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Not running as Administrator. Relaunching with elevation..."
        Start-Process -FilePath "powershell" -Verb RunAs -ArgumentList "-NoExit", "-File", "`"$PSCommandPath`""
        exit
    }

    # Ask the user for the number of DNS SANs
    $numberOfDomains = Read-Host "How many DNS SANs do you want to have in the certificate?"
    if (-not [int]::TryParse($numberOfDomains, [ref]$null) -or $numberOfDomains -le 0) {
        Write-Host "Invalid input. Please enter a valid positive number." -ForegroundColor Red
        return
    }

    # Initialize an array to store DNS SANs
    $dnsSANs = @()

    # Ask the user for each DNS SAN
    for ($i = 1; $i -le $numberOfDomains; $i++) {
        $dnsSAN = Read-Host "Enter DNS SAN $i"
        $dnsSANs += $dnsSAN
    }

    # Set the name of the certificate to be the same as the first SAN
    $certName = $dnsSANs[0]

    # Set the friendly name of the certificate to be the same as the first SAN
    $friendlyName = $certName

    # Generate the self-signed certificate with SAN
    $cert = New-SelfSignedCertificate -DnsName $dnsSANs -CertStoreLocation Cert:\LocalMachine\My -Subject $certName -FriendlyName $friendlyName

    # Export the certificate to a PFX file (optional)
    $pfxPassword = Read-Host -Prompt "Enter a password for the PFX file (optional)"
    if ($pfxPassword -ne "") {
        $pfxFilePath = Join-Path $env:USERPROFILE "Documents\$friendlyName.pfx"
        Export-PfxCertificate -Cert $cert -FilePath $pfxFilePath -Password (ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText)
        Write-Host "Certificate exported to $pfxFilePath" -ForegroundColor Green
    }

    # Ask the user if they want to import the PFX file into the machine store
    $importPfx = Read-Host "Do you want to import the PFX file into the machine store (y/n)?"
    if ($importPfx -eq "y") {
        Import-PfxCertificate -FilePath $pfxFilePath -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText) -Exportable
        Write-Host "PFX file imported into the machine store" -ForegroundColor Green
        Write-Host "Cleaning up the .pfx file." -ForegroundColor Green
        Remove-Item -Path $pfxFilePath -Force
    }
    Write-Host "Certificate exported to $cerFilePath" -ForegroundColor Green

    # Ask the user if they want to install the certificate into the Trusted Root Certification Authorities store
    $installInRoot = Read-Host "Do you want to install the certificate in the Trusted Root store (y/n)?"
    if ($installInRoot -eq "y") {
        # Export the certificate to a .cer file so it can be added to Trusted Root
        $cerFilePath = Join-Path $env:USERPROFILE "Documents\$friendlyName.cer"
        Export-Certificate -Cert $cert -FilePath $cerFilePath -Type CERT
        Import-Certificate -FilePath $cerFilePath -CertStoreLocation Cert:\LocalMachine\Root
        Write-Host "Certificate added to Trusted Root Certification Authorities" -ForegroundColor Green
        Write-Host "Cleaning up the .cer file." -ForegroundColor Green
        Remove-Item -Path $cerFilePath -Force
    }

    Write-Host "Certificate generation and installation completed." -ForegroundColor Green

}

# Run the function
CreateSelfSignedCertWithDNS
