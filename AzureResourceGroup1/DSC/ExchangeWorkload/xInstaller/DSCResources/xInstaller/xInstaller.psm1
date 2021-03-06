function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$path,

		[parameter(Mandatory = $true)]
		[System.String]
		$registryKey,

		[parameter(Mandatory = $true)]
		[System.String]
		$arguments
	)

}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$path,

		[parameter(Mandatory = $true)]
		[System.String]
		$registryKey,

		[parameter(Mandatory = $true)]
		[System.String]
		$arguments
	)

	Write-Verbose "xInstaller is invoking $path with arguments $arguments"
	$process = Start-Process -FilePath $path -ArgumentList $arguments -Wait -PassThru
	if ($process.ExitCode -gt 0 -and $process.ExitCode -ne 3010) {
		Write-Error "xInstaller operation $path $arguments failed with exit code $($process.ExitCode)!"
	} elseif ($process.ExitCode -eq -2145124329){
		Write-Warning "xInstaller operation is not applicable/needed."
	} else {
		Write-Verbose "xInstaller operation $path $arguments completed successfully."
		$parentPath = Split-Path $path
	}

	#Include this line if the resource requires a system reboot.
	#$global:DSCMachineStatus = 1
}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$path,

		[parameter(Mandatory = $true)]
		[System.String]
		$registryKey,

		[parameter(Mandatory = $true)]
		[System.String]
		$arguments
	)

	$result = $false
	if(($registryKey -ne $null) -and ($registryKey -ne "NA") -and ($registryKey -ne "N/A")){
		$result = [System.Boolean](Test-Path $registryKey)
	}	
	$result
}


Export-ModuleMember -Function *-TargetResource
