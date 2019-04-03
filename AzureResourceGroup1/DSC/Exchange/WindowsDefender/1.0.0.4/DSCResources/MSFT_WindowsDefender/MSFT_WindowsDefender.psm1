<#
    .SYNOPSIS Get state of the resource
    .EXAMPLE
        Get-TargetResource -IsSingleInstance Yes
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Yes")]
        [System.String[]]
        $IsSingleInstance
    )
    
    if (!(PlatformSupported))
    {
        Throw  "This OS version is not supported. Windows Defender DSC supports Windows 10/Windows Server 2016 and higher versions"
    }

    $Preferences = Get-MpPreference

    $ExcludeName = 'PSComputerName','ComputerID'
    $PreferenceNames = $Preferences | Get-Member -MemberType Property | ? {$_.Name -notin $ExcludeName} | % Name

    #Initialize Hashtable
    $ReturnHash = @()

    foreach ($PreferenceName in $PreferenceNames)
    {
        if($null -eq $Preferences.$PreferenceName)
        {
            $value = $null
        }
        else
        {
            $value = switch ($PreferenceName) 
            {
                'RealTimeScanDirection' 
                    {Convert-Text -Val $Preferences.$PreferenceName -Type 'ScanDirection'}
                {$_ -in 'RemediationScheduleDay','ScanScheduleDay','SignatureScheduleDay'} 
                    {Convert-Text -Val $Preferences.$PreferenceName -Type 'ScheduleDay'}
                'ScanParameters' 
                    {Convert-Text -Val $Preferences.$PreferenceName -Type 'ScanParameters'}
                'MAPSReporting'
                    {Convert-Text -Val $Preferences.$PreferenceName -Type 'MAPSReporting'}
                'SubmitSamplesConsent'
                    {Convert-Text -Val $Preferences.$PreferenceName -Type 'SubmitSamplesConsent'}
                {$_ -in 'UnknownThreatDefaultAction','LowThreatDefaultAction','ModerateThreatDefaultAction','HighThreatDefaultAction','SevereThreatDefaultAction'} 
                    {Convert-Text -Val $Preferences.$PreferenceName -Type 'ThreatAction'}
                {$_ -in '$EnableNetworkProtection','$EnableControlledFolderAccess'}
                    {Convert-Text -Val $Preferences.$PreferenceName -Type 'ASRRuleAction'}
                'CloudBlockLevel'
                    {Convert-Text -Val $Preferences.$PreferenceName -Type 'CloudBlockLevel'}
                {$_ -in 'ThreatIDDefaultAction_Actions'}
                    {Convert-TextForArray -Val $Preferences.$PreferenceName -Type 'ThreatIDDefaultAction_Actions'}
                {$_ -in 'AttackSurfaceReductionRules_Actions'}
                    {Convert-TextForArray -Val $Preferences.$PreferenceName -Type 'AttackSurfaceReductionRules_Actions'}
                Default
                    {$Preferences.$PreferenceName}
            }
          }

       $ReturnHash += @{$PreferenceName = $value}
    }
 
    Write-Verbose "Get-TargetResource successfully completed"

    $ReturnHash
}

<#
    .SYNOPSIS Set state of the resource
    .EXAMPLE
        Set-TargetResource  -IsSingleInstance yes  -DisableRealtimeMonitoring $false
#>
function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Yes")]
        [System.String[]]
        $IsSingleInstance,

        [System.String[]]
        $ExclusionPath,

        [System.String[]]
        $ExclusionExtension,

        [System.String[]]
        $ExclusionProcess,

        [ValidateSet("Both","Incoming","Outcoming")]
        [System.String]
        $RealTimeScanDirection,

        [System.UInt32]
        $QuarantinePurgeItemsAfterDelay,

        [ValidateSet("Everyday","Never","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday")]
        [System.String]
        $RemediationScheduleDay,

        [System.DateTime]
        $RemediationScheduleTime,

        [System.UInt32]
        $ReportingAdditionalActionTimeOut,

        [System.UInt32]
        $ReportingNonCriticalTimeOut,

        [System.UInt32]
        $ReportingCriticalFailureTimeOut,

        [System.UInt32]
        $ScanAvgCPULoadFactor,

        [System.Boolean]
        $CheckForSignaturesBeforeRunningScan,

        [System.UInt32]
        $ScanPurgeItemsAfterDelay,

        [System.Boolean]
        $ScanOnlyIfIdleEnabled,

        [ValidateSet("FullSCan","QuickScan")]
        [System.String]
        $ScanParameters,

        [ValidateSet("Everyday","Never","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday")]
        [System.String]
        $ScanScheduleDay,

        [System.DateTime]
        $ScanScheduleQuickScanTime,

        [System.DateTime]
        $ScanScheduleTime,

        [System.UInt32]
        $SignatureFirstAuGracePeriod,

        [System.UInt32]
        $SignatureAuGracePeriod,

        [System.String]
        $SignatureDefinitionUpdateFileSharesSources,

        [System.Boolean]
        $SignatureDisableUpdateOnStartupWithoutEngine,

        [System.String]
        $SignatureFallbackOrder,

        [ValidateSet("Everyday","Never","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday")]
        [System.String]
        $SignatureScheduleDay,

        [System.DateTime]
        $SignatureScheduleTime,

        [System.UInt32]
        $SignatureUpdateCatchupInterval,

        [System.UInt32]
        $SignatureUpdateInterval,

        [ValidateSet("Advanced","Basic","Disabled")]
        [System.String]
        $MAPSReporting,

        [System.Boolean]
        $DisablePrivacyMode,

        [System.Boolean]
        $RandomizeScheduleTaskTimes,

        [System.Boolean]
        $DisableBehaviorMonitoring,

        [System.Boolean]
        $DisableIntrusionPreventionSystem,

        [System.Boolean]
        $DisableIOAVProtection,

        [System.Boolean]
        $DisableRealtimeMonitoring,

        [System.Boolean]
        $DisableScriptScanning,

        [System.Boolean]
        $DisableArchiveScanning,

        [System.Boolean]
        $DisableAutoExclusions,

        [System.Boolean]
        $DisableCatchupFullScan,

        [System.Boolean]
        $DisableCatchupQuickScan,

        [System.Boolean]
        $DisableEmailScanning,

        [System.Boolean]
        $DisableRemovableDriveScanning,

        [System.Boolean]
        $DisableRestorePoint,

        [System.Boolean]
        $DisableScanningMappedNetworkDrivesForFullScan,

        [System.Boolean]
        $DisableScanningNetworkFiles,

        [System.Boolean]
        $UILockdown,

        [System.Int64[]]
        $ThreatIDDefaultAction_Ids,

        [ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
        [System.String[]]
        $ThreatIDDefaultAction_Actions,

        [ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
        [System.String]
        $UnknownThreatDefaultAction,

        [ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
        [System.String]
        $LowThreatDefaultAction,

        [ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
        [System.String]
        $ModerateThreatDefaultAction,

        [ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
        [System.String]
        $HighThreatDefaultAction,

        [ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
        [System.String]
        $SevereThreatDefaultAction,

        [ValidateSet("None","Always","Never")]
        [System.String]
        $SubmitSamplesConsent,

        [System.Boolean]
        $DisableBlockAtFirstSeen,

        [ValidateSet("Default","High","HighPlus","ZeroTolerance")]
        [System.String]
        $CloudBlockLevel,

        [System.UInt32]
        $CloudExtendedTimeout,

        [ValidateSet("Disabled","Enabled","AuditMode")]
        [System.String]
        $EnableNetworkProtection,

        [ValidateSet("Disabled","Enabled","AuditMode")]
        [System.String]
        $EnableControlledFolderAccess,
        
        [System.String[]]
        $AttackSurfaceReductionOnlyExclusions,

        [System.String[]]
        $ControlledFolderAccessAllowedApplications,

        [System.String[]]
        $ControlledFolderAccessProtectedFolders,

        [System.String[]]
        $AttackSurfaceReductionRules_Ids,

        [ValidateSet("Disabled","Enabled","AuditMode")]
        [System.String[]]
        $AttackSurfaceReductionRules_Actions
    )

    if (!(PlatformSupported))
    {
        Throw  "This OS version is not supported. Windows Defender DSC supports Windows 10/Windows Server 2016 and higher versions"
    }

    $Params = $PSBoundParameters
    $output = $Params.Remove('Debug')
    $output = $Params.Remove('Verbose')

    If($PSCmdlet.ShouldProcess($Params.Keys,"Update windows defender configuration"))
    {
        <# 
            When new array type configs are added/updated we want to make sure that old values are removed.
        #>
        CleanExistingConfigValue $Params
        $output = $Params.Remove('IsSingleInstance')
        <# 
            Change Windows defender configuration.
        #>
        $Params
        Set-MpPreference @Params
        Write-Verbose "Windows defender configuration successfully updated"
    }
}

<#
    .SYNOPSIS Test state of the resource
    .EXAMPLE
        Test-TargetResource -IsSingleInstance Yes -DisableRealtimeMonitoring $false -Verbose
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Yes")]
        [System.String[]]
        $IsSingleInstance,

        [System.String[]]
        $ExclusionPath,

        [System.String[]]
        $ExclusionExtension,

        [System.String[]]
        $ExclusionProcess,

        [ValidateSet("Both","Incoming","Outcoming")]
        [System.String]
        $RealTimeScanDirection,

        [System.UInt32]
        $QuarantinePurgeItemsAfterDelay,

        [ValidateSet("Everyday","Never","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday")]
        [System.String]
        $RemediationScheduleDay,

        [System.DateTime]
        $RemediationScheduleTime,

        [System.UInt32]
        $ReportingAdditionalActionTimeOut,

        [System.UInt32]
        $ReportingNonCriticalTimeOut,

        [System.UInt32]
        $ReportingCriticalFailureTimeOut,

        [System.UInt32]
        $ScanAvgCPULoadFactor,

        [System.Boolean]
        $CheckForSignaturesBeforeRunningScan,

        [System.UInt32]
        $ScanPurgeItemsAfterDelay,

        [System.Boolean]
        $ScanOnlyIfIdleEnabled,

        [ValidateSet("FullSCan","QuickScan")]
        [System.String]
        $ScanParameters,

        [ValidateSet("Everyday","Never","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday")]
        [System.String]
        $ScanScheduleDay,

        [System.DateTime]
        $ScanScheduleQuickScanTime,

        [System.DateTime]
        $ScanScheduleTime,

        [System.UInt32]
        $SignatureFirstAuGracePeriod,

        [System.UInt32]
        $SignatureAuGracePeriod,

        [System.String]
        $SignatureDefinitionUpdateFileSharesSources,

        [System.Boolean]
        $SignatureDisableUpdateOnStartupWithoutEngine,

        [System.String]
        $SignatureFallbackOrder,

        [ValidateSet("Everyday","Never","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday")]
        [System.String]
        $SignatureScheduleDay,

        [System.DateTime]
        $SignatureScheduleTime,

        [System.UInt32]
        $SignatureUpdateCatchupInterval,

        [System.UInt32]
        $SignatureUpdateInterval,

        [ValidateSet("Advanced","Basic","Disabled")]
        [System.String]
        $MAPSReporting,

        [System.Boolean]
        $DisablePrivacyMode,

        [System.Boolean]
        $RandomizeScheduleTaskTimes,

        [System.Boolean]
        $DisableBehaviorMonitoring,

        [System.Boolean]
        $DisableIntrusionPreventionSystem,

        [System.Boolean]
        $DisableIOAVProtection,

        [System.Boolean]
        $DisableRealtimeMonitoring,

        [System.Boolean]
        $DisableScriptScanning,

        [System.Boolean]
        $DisableArchiveScanning,

        [System.Boolean]
        $DisableAutoExclusions,

        [System.Boolean]
        $DisableCatchupFullScan,

        [System.Boolean]
        $DisableCatchupQuickScan,

        [System.Boolean]
        $DisableEmailScanning,

        [System.Boolean]
        $DisableRemovableDriveScanning,

        [System.Boolean]
        $DisableRestorePoint,

        [System.Boolean]
        $DisableScanningMappedNetworkDrivesForFullScan,

        [System.Boolean]
        $DisableScanningNetworkFiles,

        [System.Boolean]
        $UILockdown,

        [System.Int64[]]
        $ThreatIDDefaultAction_Ids,

        [ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
        [System.String[]]
        $ThreatIDDefaultAction_Actions,

        [ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
        [System.String]
        $UnknownThreatDefaultAction,

        [ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
        [System.String]
        $LowThreatDefaultAction,

        [ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
        [System.String]
        $ModerateThreatDefaultAction,

        [ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
        [System.String]
        $HighThreatDefaultAction,

        [ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
        [System.String]
        $SevereThreatDefaultAction,

        [ValidateSet("None","Always","Never")]
        [System.String]
        $SubmitSamplesConsent,

        [System.Boolean]
        $DisableBlockAtFirstSeen,

        [ValidateSet("Default","High","HighPlus","ZeroTolerance")]
        [System.String]
        $CloudBlockLevel,

        [System.UInt32]
        $CloudExtendedTimeout,

        [ValidateSet("Disabled","Enabled","AuditMode")]
        [System.String]
        $EnableNetworkProtection,

        [ValidateSet("Disabled","Enabled","AuditMode")]
        [System.String]
        $EnableControlledFolderAccess,
        
        [System.String[]]
        $AttackSurfaceReductionOnlyExclusions,

        [System.String[]]
        $ControlledFolderAccessAllowedApplications,

        [System.String[]]
        $ControlledFolderAccessProtectedFolders,

        [System.String[]]
        $AttackSurfaceReductionRules_Ids,

        [ValidateSet("Disabled","Enabled","AuditMode")]
        [System.String[]]
        $AttackSurfaceReductionRules_Actions
    )

    if (!(PlatformSupported))
    {
        Throw  "This OS version is not supported. Windows Defender DSC supports Windows 10/Windows Server 2016 and higher versions"
    }

    $Params = $PSBoundParameters
    
    $Get = Get-TargetResource -IsSingleInstance $Params.IsSingleInstance

    $Output = $Params.Remove('Debug')
    $Output = $Params.Remove('Verbose')
    $Output = $Params.Remove('IsSingleInstance')

    $Keys = $Get.Keys | ? {$_ -in $Params.Keys}

    $Return = $True
    
    foreach ($Key in $Keys) 
    {
    
        $InputExclusions = $Params.$key
        $CurrentExclusions = $Get.$key

        <# 
            For array types we need to compare complete array.
        #>
        if (IsArrayTypeKey($Key))
        {
            if(($null -ne $CurrentExclusions) -and ($null -ne $InputExclusions))
            {
                $Difference = (Compare-Object $CurrentExclusions $InputExclusions).InputObject

                if($Difference)
                {
                    $Return = $False
                    Write-Verbose "$Key : Input value '$InputExclusions' doesn't match with current value '$CurrentExclusions'"
                }
            }
            elseif(($null -eq $CurrentExclusions) -and ($null -eq $InputExclusions))
            {
                $Return = $True
                Write-Verbose "$Key : Both input value and current values are 'null'"
            }
            else
            {
                $Return = $False
                Write-Verbose "$Key : Either input value  or current value is 'null'"
            }        
        }
        elseif ($InputExclusions -ne $CurrentExclusions)
        {
            $Return = $False
            Write-Verbose "$Key : Input value '$InputExclusions' doesn't match with current value '$CurrentExclusions'"
        }
    }

    $Return
}

Export-ModuleMember -Function *-TargetResource


# Helper Functions

function CleanExistingConfigValue
{
    param ([parameter(Mandatory=$true)][System.Collections.Hashtable] $Params)

    $Get = Get-TargetResource -IsSingleInstance $Params.IsSingleInstance

    if ($Params.ContainsKey('ExclusionPath') -and ($Get.ExclusionPath))
    {
        remove-mppreference -ExclusionPath $Get.ExclusionPath
    }
    if ($Params.ContainsKey('ExclusionProcess') -and ($Get.ExclusionProcess))
    {
        remove-mppreference -ExclusionProcess $Get.ExclusionProcess
    }
    if ($Params.ContainsKey('ExclusionExtension') -and ($Get.ExclusionExtension))
    {
        remove-mppreference -ExclusionExtension $Get.ExclusionExtension
    }
    if ($Params.ContainsKey('ThreatIDDefaultAction_Ids') -and ($Get.ThreatIDDefaultAction_Ids))
    {
        remove-mppreference -ThreatIDDefaultAction_Ids $Get.ThreatIDDefaultAction_Ids
    }
    if ($Params.ContainsKey('AttackSurfaceReductionOnlyExclusions') -and ($Get.AttackSurfaceReductionOnlyExclusions))
    {
        remove-mppreference -AttackSurfaceReductionOnlyExclusions $Get.AttackSurfaceReductionOnlyExclusions
    }
    if ($Params.ContainsKey('ControlledFolderAccessAllowedApplications') -and ($Get.ControlledFolderAccessAllowedApplications))
    {
        remove-mppreference -ControlledFolderAccessAllowedApplications $Get.ControlledFolderAccessAllowedApplications
    }
    if ($Params.ContainsKey('ControlledFolderAccessProtectedFolders') -and ($Get.ControlledFolderAccessProtectedFolders))
    {
        remove-mppreference -ControlledFolderAccessProtectedFolders $Get.ControlledFolderAccessProtectedFolders
    }
    if ($Params.ContainsKey('AttackSurfaceReductionRules_Ids') -and ($Get.AttackSurfaceReductionRules_Ids))
    {
        remove-mppreference -AttackSurfaceReductionRules_Ids $Get.AttackSurfaceReductionRules_Ids
    }
}

function Convert-Text
{
    param(
    [parameter(Mandatory=$true)][Byte]$Val,
    [parameter(Mandatory=$true)][string]$Type
    )
    
    switch ($Type)
    {
        'ScanDirection'
        {
            switch ($Val)
            {
                0 {'Both'}
                1 {'Incoming'}
                2 {'Outcoming'}
            }
        }
        'ScheduleDay'
        {
            switch ($Val)
            {
                0 {'Everyday'}
                1 {'Sunday'}
                2 {'Monday'}
                3 {'Tuesday'}
                4 {'Wednesday'}
                5 {'Thursday'}
                6 {'Friday'}
                7 {'Saturday'}
                8 {'Never'}
            }
        }
        'ScanParameters'
        {
    
            switch ($Val)
            {
                1 {'Quick scan'}
                2 {'Full scan'}
            }
    
        }
        'MAPSReporting'
        {
            switch ($Val)
            {
                0 {'Disabled'}
                1 {'Basic'}
                2 {'Advanced'}
            }
        }
        'SubmitSamplesConsent'
        {

            switch ($Val)
            {
                0 {'None'}
                1 {'Always'}
                2 {'Never'}
            }
        }
        'ThreatAction'
        {
            switch ($Val)
            {
                1 {'Clean'}
                2 {'Quarantine'}
                3 {'Remove'}
                6 {'Allow'}
                8 {'UserDefined'}
                9 {'NoAction'}
                10 {'Block'}
            }
        }
        'CloudBlockLevel'
        {
            switch ($Val)
            {
                0 {'Default'}
                2 {'High'}
                4 {'HighPlus'}
                6 {'ZeroTolerance'}
            }
        }
        'ASRRuleAction'
        {
            switch ($Val)
            {
                0 {'Disabled'}
                1 {'Enabled'}
                2 {'AuditMode'}
            }
        }
    }
}

function Convert-TextForArray
{    
    param(
    [parameter(Mandatory=$true)][Byte[]]$Values,
    [parameter(Mandatory=$true)][string]$Type
    )

    $outStrings = @()

    switch ($Type)
    {
        'ThreatIDDefaultAction_Actions'
        {
           foreach ($Value in $Values)
           {
               switch ($Value)
               {
                   1  {$outStrings += 'Clean'}
                   2  {$outStrings += 'Quarantine'}
                   3  {$outStrings += 'Remove'}
                   6  {$outStrings += 'Allow'}
                   8  {$outStrings += 'UserDefined'}
                   9  {$outStrings += 'NoAction'}
                   10 {$outStrings += 'Block'}
               }
           }
        }
        'AttackSurfaceReductionRules_Actions'
        {
           foreach ($Value in $Values)
           {
               switch ($Value)
               {
                   0  {$outStrings += 'Disabled'}
                   1  {$outStrings += 'Enabled'}
                   2  {$outStrings += 'AuditMode'}
               }
           }
        }
     }

     return ,$outStrings
}

function PlatformSupported
{
    #WindowsDefender DSC is only supported on Windows 10+ and Windows Server 2016+
    if ([System.Environment]::OSVersion.Version.Major -ge 10)
    {
        return $true;
    
    }
    else
    {
        return $false;
    }
}

function IsArrayTypeKey
{
    param([parameter(Mandatory=$true)] [System.String] $KeyName)


    if (($KeyName -eq 'ExclusionPath') -or ($KeyName -eq 'ExclusionProcess') -or ($KeyName -eq 'ExclusionExtension') -or
        ($KeyName -eq 'AttackSurfaceReductionOnlyExclusions') -or ($KeyName -eq 'ControlledFolderAccessAllowedApplications') -or
        ($KeyName -eq 'ControlledFolderAccessProtectedFolders') -or ($KeyName -eq 'AttackSurfaceReductionRules_Ids') -or
        ($KeyName -eq 'AttackSurfaceReductionRules_Actions') -or ($KeyName -eq 'ThreatIDDefaultAction_Ids') -or
        ($KeyName -eq 'ThreatIDDefaultAction_Actions'))
    {
         return $true
    }
    else
    {
        return $false
    }
}
