
configuration NPS
{

    Import-DscResource -ModuleName xComputerManagement,PSDesiredStateConfiguration

    Node "localhost"
    {
        LocalConfigurationManager
        {
            DebugMode = "All"
            RebootNodeIfNeeded = $true
        }

        WindowsFeature NPAS   #install NPS
        {
            Ensure = "Present"
            Name   = "NPAS"
        }

        Script NPSExtensions
        {
            SetScript = {
                $NPSDLUrl="https://download.microsoft.com/download/B/F/F/BFFB4F12-9C09-4DBC-A4AF-08E51875EEA9/NpsExtnForAzureMfaInstaller.exe"

                $tempfile = [System.IO.Path]::GetTempFileName()
                $folder = [System.IO.Path]::GetDirectoryName($tempfile)

                $webclient = New-Object System.Net.WebClient
                $webclient.DownloadFile($NPSDLUrl, $tempfile)

                Rename-Item -Path $tempfile -NewName "NpsExtnForAzureMfaInstaller.exe"
                $MSIPath = $folder + "\NpsExtnForAzureMfaInstaller.exe"

                Invoke-Expression "$MSIPath /passive /norestart"
            }

            GetScript =  { @{} }
            TestScript = { 
                return Test-Path "$env:TEMP\NpsExtnForAzureMfaInstaller.exe" 
            }
        } 
    }
}