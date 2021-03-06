function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$SourcePath,
		
		[parameter(Mandatory = $true)]
		[System.String]
		$FileName,

        [parameter(Mandatory = $true)]
		[System.String]
		$DestinationDirectoryPath
	)

	#Write-Verbose "Use this cmdlet to deliver information about command processing."

	#Write-Debug "Use this cmdlet to write debug information while troubleshooting."

	$returnValue = @{
		SourcePath = $SourcePath
		FileName  = $FileName
        DestinationDirectoryPath = $DestinationDirectoryPath
	}
    $returnValue
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$SourcePath,
		
		[parameter(Mandatory = $true)]
		[System.String]
		$FileName,

        [parameter(Mandatory = $true)]
		[System.String]
		$DestinationDirectoryPath
	)

    Write-Verbose "Create Destination Directory"
	if(!(Test-Path $DestinationDirectoryPath))
	{
		New-Item -Path $DestinationDirectoryPath -ItemType Directory -Force
	}
	
    $output = Join-Path $DestinationDirectoryPath $FileName
    Write-Verbose "Start to download file from $SourcePath"
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($SourcePath, $output)
    Write-Verbose "Complete download file from $SourcePath"
}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$SourcePath,
		
		[parameter(Mandatory = $true)]
		[System.String]
		$FileName,

        [parameter(Mandatory = $true)]
		[System.String]
		$DestinationDirectoryPath
	)
	$output = Join-Path $DestinationDirectoryPath $FileName
	Test-Path $output
}


Export-ModuleMember -Function *-TargetResource

