<#
If you want to use PowerShell 7 in the ISE, you can use this script.
This script initializes a PowerShell 7 runspace in the ISE.
Open it in the ISE and run it.
#>

Function Initialize-PowerShell7 {

    function New-OutOfProcRunspace {

        param($ProcessId)

        $connectionInfo = New-Object -TypeName System.Management.Automation.Runspaces.NamedPipeConnectionInfo -ArgumentList @($ProcessId)

        $TypeTable = [System.Management.Automation.Runspaces.TypeTable]::LoadDefaultTypeFiles()

        $Runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($connectionInfo, $Host, $TypeTable)

        $Runspace.Open()

        $ps = [powershell]::Create().AddScript({

                $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText

            })

        $ps.Runspace = $Runspace

        $ps.Invoke()

        $ps.Dispose()

        $Runspace

    }

    $Process = Start-Process PWSH -ArgumentList @("-NoExit") -PassThru -WindowStyle Hidden

    $Runspace = New-OutOfProcRunspace -ProcessId $Process.Id

    $Host.PushRunspace($Runspace)

}

Initialize-PowerShell7