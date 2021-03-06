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
		$DestinationDirectoryPath
	)

	#Write-Verbose "Use this cmdlet to deliver information about command processing."

	#Write-Debug "Use this cmdlet to write debug information while troubleshooting."


	
	$returnValue = @{
		SourcePath = $SourcePath
        DestinationDirectoryPath = $DestinationDirectoryPath
	}
    $returnValue
}

function PSUsing([System.IDisposable]$inputObject, [ScriptBlock]$scriptBlock)
{
    try
    {
        & $scriptBlock
    }
    finally
    {
        if ($inputObject)
        {
            if (-not $inputObject.PSBase)
            {
                $inputObject.Dispose()
            }
            else
            {
                $inputObject.PSBase.Dispose()
            }
        }
    }
}

function Download-File
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$uri,

        [Parameter(Mandatory = $true)]
        [string]$pathName
    )
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $resut = $false
    try
    {
        $request = [System.Net.HttpWebRequest]::Create($uri)
        $request.Timeout = 3600000 
        $response = $request.GetResponse()
        $sizeInBytes = $response.ContentLength

        Write-Verbose -Message "Downloading $uri ($sizeInBytes bytes) to '$pathName'..." -Verbose

        $bufferSize = 1MB
        $lastDisplayTime = $stopwatch.Elapsed
        PSUsing ($responseStream = $response.GetResponseStream()) {
            PSUsing ($targetStream = New-Object System.IO.FileStream($pathName, [System.IO.FileMode]::Create)) {
                $buffer = New-Object byte[]($bufferSize)
                $count = $responseStream.Read($buffer, 0, $buffer.length)
                $downloadedBytes = $count
                while ($count -gt 0)
                {
                    $targetStream.Write($buffer, 0, $count)
                    $count = $responseStream.Read($buffer, 0, $buffer.length)
                    $downloadedBytes = $downloadedBytes + $count

                    $percent = [int](100 * ($downloadedBytes / $sizeInBytes))
                                 
                    if(([int]$stopwatch.Elapsed.TotalSeconds - [int]$lastDisplayTime.TotalSeconds) -gt 30)
                    {
                        $status = "Downloaded ($([System.Math]::Floor($downloadedBytes / 1MB))MB of $([System.Math]::Floor($sizeInBytes / 1MB))MB). (Elapsed: $($stopwatch.Elapsed))"
                        $lastDisplayTime = $stopwatch.Elapsed
                        Write-Verbose "Downloading $uri ($sizeInBytes bytes) to '$pathName'... '$status'. '$percent'% is completed" -Verbose
                    }
                }
            }
        }

        Write-Verbose -Message "Downloaded $uri ($sizeInBytes bytes) to '$pathName'. (Elapsed: $($stopwatch.Elapsed))" -Verbose
        $resut = $true
    }
    catch
    {}
    finally
    {
        $resut
    }
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
		$DestinationDirectoryPath
	)

    Write-Verbose "Create Destination Directory"
    New-Item -Path $DestinationDirectoryPath -ItemType Directory -Force

    $fileName = "{0}.iso" -f (Get-Date).ToString("yyyy-MM-dd-hh-mm-ss")
    $output = Join-Path $DestinationDirectoryPath $fileName

    $retry = 0
    $result = $false
    do
    {
        $result = Download-File -uri $SourcePath -pathName $output
        if(-not $result)
        {
            Write-Verbose "Download file failed. will retry. Current retry count $retry"
            Start-Sleep -Seconds 30
        }
        $retry = $retry + 1

    }while (($retry -le 5) -and (-not $result))

    if($result)
    {
        Write-Verbose "Mount the image from $output"
        $image = Mount-DiskImage -ImagePath $output -PassThru
        $driveLetter = ($image | Get-Volume).DriveLetter

        Write-Verbose "Copy files to destination directory: $DestinationDirectoryPath"
        Robocopy.exe ("{0}:" -f $driveLetter) $DestinationDirectoryPath /E | Out-Null
    
        Write-Verbose "Dismount the image from $output"
        Dismount-DiskImage -ImagePath $output
    
        Write-Verbose "Delete the temp file: $output"
        Remove-Item -Path $output -Force
    }
    else
    {
        Throw "Fail to download the file after exhaust retry limit"
    }

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
		$DestinationDirectoryPath
	)

	Test-Path $DestinationDirectoryPath
}


Export-ModuleMember -Function *-TargetResource

