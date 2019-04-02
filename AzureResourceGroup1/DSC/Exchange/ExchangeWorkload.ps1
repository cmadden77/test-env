#
# Install exchange and prereqs
#

configuration InstallAndConfigureExchange
{
	param
    (
		[Parameter(Mandatory=$true)]
		[String]$DomainName,

		[Parameter(Mandatory=$true)]
		[String]$StorageSize,

		[Parameter(Mandatory=$true)]
		[PSCredential]$VMAdminCreds,

		[Parameter(Mandatory=$true)]
		[String]$Location
	)

	$DomainCreds = [System.Management.Automation.PSCredential]$DomainFQDNCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($VMAdminCreds.UserName)", $VMAdminCreds.Password)


	Import-DscResource -ModuleName xDisk;
    Import-DscResource -ModuleName xExchange;
	Import-DscResource -ModuleName xPendingReboot;
	#Import-DscResource -ModuleName xPSDesiredStateConfiguration;
	#Import-DscResource -ModuleName xPSWindowsUpdate;	
    #Import-DscResource -ModuleName 'PSDesiredStateConfiguration';
	#Import-DscResource -ModuleName xActiveDirectory;
	#Import-DscResource -ModuleName xDownloadFile;
	#Import-DscResource -ModuleName xDownloadISO;
	#Import-DscResource -ModuleName xExchangeValidate;
	#Import-DscResource -ModuleName xExtract;
	#Import-DscResource -ModuleName xInstaller;

	# Downloaded file storage location
	$downloadPath = "$env:SystemDrive\DownloadsForDSC";
	$exchangeInstallerPath = "$env:SystemDrive\InstallerExchange";
	$diskNumber = 2;

	Node localhost
    {
		xWaitforDisk Disk2
        {
            DiskNumber = $diskNumber
            RetryIntervalSec = 60
            RetryCount = 60
        }
        xDisk Volume
        {
			DiskNumber = $diskNumber
            DriveLetter = 'F'
			DependsOn = '[xWaitforDisk]Disk2'
        }
		# Reboot node if necessary no longer needed
		xPendingReboot RebootPostInstallNet45
        {
            Name      = "AfterNet452"
			DependsOn = "[xDisk]Volume"
        }
		# Install Exchange 2016 Pre-requisits | Reference: https://technet.microsoft.com/en-us/library/bb691354(v=exchg.160).aspx
		# Active Directory
		WindowsFeature RSATADDS {
			Name = "RSAT-ADDS"
            Ensure = "Present"
			DependsOn = "[xPendingReboot]RebootPostInstallNet45"
		}
		# Media Foundation
		WindowsFeature MediaFoundationInstall 
        {
            Name = "Server-Media-Foundation"
			Ensure = "Present"
			DependsOn = "[WindowsFeature]RSATADDS"
        }
		xPendingReboot RebootPostMediaFoundationInstall
        {
           	Name = "AfterADDSInstall"
           	DependsOn = "[WindowsFeature]MediaFoundationInstall"
        }
		WindowsFeature Net45Features {
			Name = "NET-Framework-45-Features"
            Ensure = "Present"
			DependsOn = "[xPendingReboot]RebootPostMediaFoundationInstall"
		}
		WindowsFeature RPCOverHTTPProxy {
			Name = "RPC-over-HTTP-proxy"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]Net45Features"
		}
		WindowsFeature RSATClustering {
			Name = "RSAT-Clustering"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]RPCOverHTTPProxy"
		}
		WindowsFeature RSATClusteringCmd {
			Name = "RSAT-Clustering-CmdInterface"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]RSATClustering"
		}
		WindowsFeature RSATClusteringMgmt {
			Name = "RSAT-Clustering-Mgmt"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]RSATClusteringCmd"
		}
		WindowsFeature RSATClusteringPS {
			Name = "RSAT-Clustering-PowerShell"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]RSATClusteringMgmt"
		}
		WindowsFeature WASProcessModel {
			Name = "WAS-Process-Model"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]RSATClusteringPS"
		}
		WindowsFeature WebAspNet45 {
			Name = "Web-Asp-Net45"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WASProcessModel"
		}
		WindowsFeature WebBasicAuth {
			Name = "Web-Basic-Auth"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebAspNet45"
		}
		WindowsFeature WebClientAuth {
			Name = "Web-Client-Auth"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebBasicAuth"
		}
		WindowsFeature WebDigestAuth {
			Name = "Web-Digest-Auth"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebClientAuth"
		}
		WindowsFeature WebDirBrowsing {
			Name = "Web-Dir-Browsing"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebDigestAuth"
		}
		WindowsFeature WebDynCompression {
			Name = "Web-Dyn-Compression"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebDirBrowsing"
		}
		WindowsFeature WebHttpErrors {
			Name = "Web-Http-Errors"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebDynCompression"
		}
		WindowsFeature WebHttpLogging {
			Name = "Web-Http-Logging"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebHttpErrors"
		}
		WindowsFeature WebHttpRedirect {
			Name = "Web-Http-Redirect"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebHttpLogging"
		}
		WindowsFeature WebHttpTracing {
			Name = "Web-Http-Tracing"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebHttpRedirect"
		}
		WindowsFeature WebISAPIExt {
			Name = "Web-ISAPI-Ext"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebHttpTracing"
		}
		WindowsFeature WebISAPIFilter {
			Name = "Web-ISAPI-Filter"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebISAPIExt"
		}
		WindowsFeature WebLgcyMgmtConsole {
			Name = "Web-Lgcy-Mgmt-Console"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebISAPIFilter"
		}
		WindowsFeature WebMetabase {
			Name = "Web-Metabase"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebLgcyMgmtConsole"
		}
		WindowsFeature WebMgmtConsole {
			Name = "Web-Mgmt-Console"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebMetabase"
		}
		WindowsFeature WebMgmtService {
			Name = "Web-Mgmt-Service"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebMgmtConsole"
		}
		WindowsFeature WebNetExt45 {
			Name = "Web-Net-Ext45"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebMgmtService"
		}
		WindowsFeature WebRequestMonitor {
			Name = "Web-Request-Monitor"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebNetExt45"
		}
		WindowsFeature WebServer {
			Name = "Web-Server"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebRequestMonitor"
		}
		WindowsFeature WebStatCompression {
			Name = "Web-Stat-Compression"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebServer"
		}
		WindowsFeature WebStaticContent {
			Name = "Web-Static-Content"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebStatCompression"
		}
		WindowsFeature WebWindowsAuth {
			Name = "Web-Windows-Auth"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebStaticContent"
		}
		WindowsFeature WebWMI {
			Name = "Web-WMI"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebWindowsAuth"
		}
		WindowsFeature WindowsIdentityFoundation {
			Name = "Windows-Identity-Foundation"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]WebWMI"
		}
		WindowsFeature NETWCFHTTPActivation45 {
			Name = "NET-WCF-HTTP-Activation45"
            Ensure = "Present"
			DependsOn = "[WindowsFeature]NETWCFHTTPActivation45"
		}
		# Install Exchange 2016 CU12
        xExchInstall InstallExchange
        {
            Path = "$exchangeInstallerPath\setup.exe"
            Arguments = "/Mode:Install /Role:Mailbox /OrganizationName:ExchOrg /TargetDir:F:\Exchange /IAcceptExchangeServerLicenseTerms"
            Credential = $DomainCreds
            DependsOn = "[WindowsFeature]WindowsIdentityFoundation"
			PsDscRunAsCredential = $DomainCreds
        }
		# Reboot node if needed
		LocalConfigurationManager 
        {
			ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $True
        }
	}
}
