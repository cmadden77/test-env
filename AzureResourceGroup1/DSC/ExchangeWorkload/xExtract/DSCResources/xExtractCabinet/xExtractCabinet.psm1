function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$source,

		[parameter(Mandatory = $true)]
		[System.String]
		$destination
	)

}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$source,

		[parameter(Mandatory = $true)]
		[System.String]
		$destination,

		[System.String]
		$arguments
	)

	if(Test-Path $destination){
		Write-Verbose "Removing old directory $destination"
		Remove-Item -Path $destination -Recurse -Force -ErrorAction SilentlyContinue
	}
	
	Write-Verbose "xExtractCabinet is creating new directory $destination"
	New-Item -Path $destination -ItemType Directory -ErrorAction SilentlyContinue
	$arg = "/extract:$destination\ /quiet"
	if(($arguments -ne $null) -and ($arguments -ne "")){
		Write-Verbose "xExtractCabinet is using given arguments $arguments"
		$arg = $arguments
	}
	
	Write-Verbose "xExtractCabinet is invoking $source with arguments $arg"
	$process = Start-Process -FilePath $source -ArgumentList $arg -Wait -PassThru
	if ($process.ExitCode -gt 0 -and $process.ExitCode -ne 3010) {
		Write-Error "xExtractCabinet operation on $source with arguments $arg failed with exit code $($process.ExitCode)!"
	} elseif ($process.ExitCode -eq -2145124329){
		Write-Warning "xExtractCabinet operation is not applicable/needed."
	} else {
		Write-Verbose "xExtractCabinet operation on $source with arguments $arg completed."
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
		$source,

		[parameter(Mandatory = $true)]
		[System.String]
		$destination,

		[System.String]
		$arguments
	)

	# Check if path exists and have atleast one file inside it
	$result = (Test-Path $destination) -and ((Get-ChildItem $destination | measure).Count -ne 0)
	if($result){
		Write-Verbose "Target path $destination exists, skipping extracting file $source"
	}
	else {
		Write-Verbose "Target path $destination either doesn't exists or is empty. Extracting file $source"
	}

	$result
}


Export-ModuleMember -Function *-TargetResource

