<#
.SYNOPSIS
   (E)xVC-vMotion Helper
   This script gives the function xMove-VM from xMove-VM.ps1 1.2 written by William Lam a wizard driven workflow to easily select the workloads to migrate.

   Offcourse it CAN use the same inputs on commandline, but without gives you a nice wizard to walk you through every step including the selection of every source en destination parameter needed for the move.
   
   The xMove-VM function demonstrates an xVC-vMotion where a running Virtual Machine
   is live migrated between two vCenter Servers which are NOT part of the
   same SSO Domain which is only available using the vSphere 6.0 API.

   This script also supports live migrating a running Virtual Machine between
   two vCenter Servers that ARE part of the same SSO Domain (aka Enhanced Linked Mode)

   This script also supports migrating VMs connected to both a VSS/VDS as well as having multiple vNICs

   This script also supports migrating to/from VMware Cloud on AWS (VMC)
.NOTES
   ================================
   name     : (E)xVC-vMotion Helper
   filename : ExVC-Helper.ps1
   author   : Jan Jaap van Santen
   github   : janjaaps
   email    : janjaap@scict.nl
   blog     : https://scict.nl/
   ================================
.LINK
   https://scict.nl/ExVC-vMotion-Helper
.LINK
   https://github.com/janjaaps
.LINK
   http://www.virtuallyghetto.com/2016/05/automating-cross-vcenter-vmotion-xvc-vmotion-between-the-same-different-sso-domain.html
.LINK
   https://github.com/lamw

.INPUTS
   sourceVCConnection, destVCConnection, vm, switchtype, switch,
   cluster, resourcepool, datastore, vmhost, vmnetworks, $xvctype, $uppercaseuuid
.OUTPUTS
   Console output
#>


### VARS DONT TOUCH
$version = "v1.1"
### VARS

# Variables that can be defined as defaults
$sourceVC = "vcenter60-1.primp-industries.com"
$sourceVCUsername = "administrator@vghetto.local"
$sourceVCPassword = "VMware1!"
$destVC = "vcenter60-3.primp-industries.com"
$destVCUsername = "administrator@vghetto.local"
$destVCpassword = "VMware1!"
$datastorename = "la-datastore1"
$resourcepool = "WorkloadRP"
$vmhostname = "vesxi60-5.primp-industries.com"
$vmnetworkname = "LA-VM-Network1"
$switchname = "LA-VDS"
$switchtype = "vds"
$ComputeXVC = 1
$UppercaseUUID = $false

$doReport = $True # Option to report/mail
$logfile = "U:\Powershel (E)xVC-vMotion Helper\ExVC-vMotion-Helper.log"
if ($doReport) { 
    if ([System.IO.File]::Exists($logfile)) { Clear-Content $logfile }
}



##### xMove-VM by William Lam
Function xMove-VM {
    param(
    [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)
    ]
    [VMware.VimAutomation.ViCore.Util10.VersionedObjectImpl]$sourcevc,
    [VMware.VimAutomation.ViCore.Util10.VersionedObjectImpl]$destvc,
    [String]$destVCusername,
    [String]$destVCpassword,
    [String]$vm,
    [String]$switchtype,
    [String]$switch,
    [String]$cluster,
    [String]$resourcepool,
    [String]$datastore,
    [String]$vmhost,
    [String]$vmnetworks,
    [Int]$xvctype,
    [Boolean]$uppercaseuuid
    )

    # Retrieve Source VC SSL Thumbprint
    $vcurl = "https://" + $destVC
add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;

            public class IDontCarePolicy : ICertificatePolicy {
            public IDontCarePolicy() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy
    # Need to do simple GET connection for this method to work
    Invoke-RestMethod -Uri $VCURL -Method Get | Out-Null

    $endpoint_request = [System.Net.Webrequest]::Create("$vcurl")
    # Get Thumbprint + add colons for a valid Thumbprint
    $destVCThumbprint = ($endpoint_request.ServicePoint.Certificate.GetCertHashString()) -replace '(..(?!$))','$1:'

    # Source VM to migrate
    $vm_view = Get-View (Get-VM -Server $sourcevc -Name $vm) -Property Config.Hardware.Device

    # Dest Datastore to migrate VM to
    $datastore_view = (Get-Datastore -Server $destVCConn -Name $datastore)

    # Dest Cluster/ResourcePool to migrate VM to
    if($cluster) {
        $cluster_view = (Get-Cluster -Server $destVCConn -Name $cluster)
        $resource = $cluster_view.ExtensionData.resourcePool
    } else {
        $rp_view = (Get-ResourcePool -Server $destVCConn -Name $resourcepool)
        $resource = $rp_view.ExtensionData.MoRef
    }

    # Dest ESXi host to migrate VM to
    $vmhost_view = (Get-VMHost -Server $destVCConn -Name $vmhost)

    # Find all Etherenet Devices for given VM which
    # we will need to change its network at the destination
    $vmNetworkAdapters = @()
    $devices = $vm_view.Config.Hardware.Device
    foreach ($device in $devices) {
        if($device -is [VMware.Vim.VirtualEthernetCard]) {
            $vmNetworkAdapters += $device
        }
    }

    # Relocate Spec for Migration
    $spec = New-Object VMware.Vim.VirtualMachineRelocateSpec
    $spec.datastore = $datastore_view.Id
    $spec.host = $vmhost_view.Id
    $spec.pool = $resource

    # Relocate Spec Disk Locator
    if($xvctype -eq 1){
        $HDs = Get-VM -Server $sourcevc -Name $vm | Get-HardDisk
        $HDs | %{
            $disk = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator
            $disk.diskId = $_.Extensiondata.Key
            $SourceDS = $_.FileName.Split("]")[0].TrimStart("[")
            $DestDS = Get-Datastore -Server $destvc -name $sourceDS
            $disk.Datastore = $DestDS.ID
            $spec.disk += $disk
        }
    }

    # Service Locator for the destination vCenter Server
    # regardless if its within same SSO Domain or not
    $service = New-Object VMware.Vim.ServiceLocator
    $credential = New-Object VMware.Vim.ServiceLocatorNamePassword
    $credential.username = $destVCusername
    $credential.password = $destVCpassword
    $service.credential = $credential
    # For some xVC-vMotion, VC's InstanceUUID must be in all caps
    # Haven't figured out why, but this flag would allow user to toggle (default=false)
    if($uppercaseuuid) {
        $service.instanceUuid = $destVC.InstanceUuid
    } else {
        $service.instanceUuid = ($destVC.InstanceUuid).ToUpper()
    }
    $service.sslThumbprint = $destVCThumbprint
    $service.url = "https://$destVC"
    $spec.service = $service

    # Create VM spec depending if destination networking
    # is using Distributed Virtual Switch (VDS) or
    # is using Virtual Standard Switch (VSS)
    $count = 0
    if($switchtype -eq "vds") {
        foreach ($vmNetworkAdapter in $vmNetworkAdapters) {
            # New VM Network to assign vNIC
            $vmnetworkname = ($vmnetworks -split ",")[$count]

            # Extract Distributed Portgroup required info
            $dvpg = Get-VDPortgroup -Server $destvc -Name $vmnetworkname
            $vds_uuid = (Get-View $dvpg.ExtensionData.Config.DistributedVirtualSwitch).Uuid
            $dvpg_key = $dvpg.ExtensionData.Config.key

            # Device Change spec for VSS portgroup
            $dev = New-Object VMware.Vim.VirtualDeviceConfigSpec
            $dev.Operation = "edit"
            $dev.Device = $vmNetworkAdapter
            $dev.device.Backing = New-Object VMware.Vim.VirtualEthernetCardDistributedVirtualPortBackingInfo
            $dev.device.backing.port = New-Object VMware.Vim.DistributedVirtualSwitchPortConnection
            $dev.device.backing.port.switchUuid = $vds_uuid
            $dev.device.backing.port.portgroupKey = $dvpg_key
            $spec.DeviceChange += $dev
            $count++
        }
    } else {
        foreach ($vmNetworkAdapter in $vmNetworkAdapters) {
            # New VM Network to assign vNIC
            $vmnetworkname = ($vmnetworks -split ",")[$count]

            # Device Change spec for VSS portgroup
            $dev = New-Object VMware.Vim.VirtualDeviceConfigSpec
            $dev.Operation = "edit"
            $dev.Device = $vmNetworkAdapter
            $dev.device.backing = New-Object VMware.Vim.VirtualEthernetCardNetworkBackingInfo
            $dev.device.backing.deviceName = $vmnetworkname
            $spec.DeviceChange += $dev
            $count++
        }
    }

    Write-Host "`nMigrating $vm from $sourceVC to $destVC ...`n"

    # Issue Cross VC-vMotion
    
    $task = $vm_view.RelocateVM_Task($spec,"defaultPriority")
    
    #$task = $vm_view.RelocateVM_Task($spec,"defaultPriority")
    #$task1 = Get-Task -Id ("Task-$($task.value)")
    #$task1 | Wait-Task
}



##### WriteLogScreen
function WriteLogScreen {
   Param ([string]$logstring)
   if ($doReport) { $logstring | out-file -Filepath $logfile -append }
   write-host "$logstring" -Fore DarkGray
}


##### using VMware.VimAutomation.Core
cls
$Loaded = $False
if (((Get-Module -Name VMware.VimAutomation.Core) -eq $null) -and ((Get-Module -ListAvailable -Name VMware.VimAutomation.Core) -ne $null)) {  
    Write-Output "loading the VMware Core Module..."  
    Import-Module -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue
    Import-Module -Name VMware.VimAutomation.vds -ErrorAction SilentlyContinue
    if ((Get-Module -Name VMware.VimAutomation.Core) -eq $null) {  
        # Error out if loading fails  
        WriteLogScreen "`nERROR: Cannot load the VMware Module. Is the PowerCLI installed?" 
        WriteLogScreen "Press any key to exit and launch a browser to the VMware PowerCLI page."
        $empty = Read-Host -Prompt 'Press enter to continue'
        Start-Process -FilePath "https://code.vmware.com/web/dp/tool/vmware-powercli/" 
        exit
    }
    $Loaded = $True  
} elseif (((Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null ) -and ((Get-Module -Name VMware.VimAutomation.Core) -eq $null) -and ($Loaded -ne $True)) {  
    Write-Output "loading the VMware Core Snapin..."  
    Add-PSSnapin -PassThru VMware.VimAutomation.Core -ErrorAction SilentlyContinue
    if ((Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null ) {  
        # Error out if loading fails  
        WriteLogScreen "`nERROR: Cannot load the VMware Snapin or Module. Is the PowerCLI installed?"
        WriteLogScreen "Press any key to exit and launch a browser to the VMware PowerCLI page."
        $empty = Read-Host -Prompt 'Press enter to continue'
        Start-Process -FilePath "https://code.vmware.com/web/dp/tool/vmware-powercli/" 
        exit
    }  
}


##### LOGO
cls
WriteLogScreen "`n/------------------------------------------------------------------------------------------------------------------------------\" 
WriteLogScreen "|   __   __ __                    ___                               _    _                               _                     |"
WriteLogScreen "|  / /  /__\\ \ __  __ /\   /\   / __\       __   __  /\/\    ___  | |_ (_)  ___   _ __     /\  /\  ___ | | _ __    ___  _ __  |"
WriteLogScreen "| | |  /_\   | |\ \/ / \ \ / /  / /    _____ \ \ / / /    \  / _ \ | __|| | / _ \ | '_ \   / /_/ / / _ \| || '_ \  / _ \| '__| |"
WriteLogScreen "| | | //__   | | >  <   \ V /  / /___ |_____| \ V / / /\/\ \| (_) || |_ | || (_) || | | | / __  / |  __/| || |_) ||  __/| |    |"
WriteLogScreen "| | | \__/   | |/_/\_\   \_/   \____/          \_/  \/    \/ \___/  \__||_| \___/ |_| |_| \/ /_/   \___||_|| .__/  \___||_|    |"
WriteLogScreen "|  \_\      /_/                                                                                            |_|            $version |" 
WriteLogScreen "\------------------------------------------------------------------------------------------------------------------------------/`n" 


##### Start the workflow
Set-PowerCLIConfiguration -DisplayDeprecationWarnings $false -scope session -Confirm:$False | Out-Null
Set-PowerCLIConfiguration -InvalidCertificateAction warn -scope session -Confirm:$False | Out-Null
Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Confirm:$false -Scope Session | Out-Null
$global:DefaultVIServer = $null
$global:DefaultVIServers = $null
### Source vCenter
WriteLogScreen "`nStep 1. Source vCenter"
$string_sourceVC = read-host -Prompt "Enter the source vCenters FQDN [$sourceVC]"
if ([string]::IsNullOrWhiteSpace($string_sourceVC)) { $string_sourceVC = $sourceVC }

$string_sourceVCUsername = read-host -Prompt "Enter the source vCenters Username [$sourceVCUsername]"
if ([string]::IsNullOrWhiteSpace($string_sourceVCUsername)) { $string_sourceVCUsername = $sourceVCUsername }

$string_sourceVCPassword = read-host -assecurestring "Enter the source vCenters Password [********]"
if ([string]::IsNullOrWhiteSpace($string_sourceVCPassword)) { $string_sourceVCPassword = $sourceVCPassword }

$sourceVCCredential=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $string_sourceVCUsername, $string_sourceVCPassword


#
#
#
#############################################################
### Destination vCenter
#############################################################
WriteLogScreen "`nStep 2. Destination vCenter"
$string_destVC = read-host -Prompt "Enter the destination vCenters FQDN [$destVC]"
if ([string]::IsNullOrWhiteSpace($string_destVC)) { $string_destVC = $destVC }

$string_destcredresuse = read-host -Prompt "Use the same credentials for the destination vCenter? [Y/N]"
if ( $string_destcredresuse -ieq "Y" ) { 
    $string_destVCUsername = $string_sourceVCUsername
    $string_destVCPassword = $string_sourceVCPassword
    $destVCCredential = $sourceVCCredential
} else {
    $string_destVCUsername = read-host -Prompt "Enter the destination vCenters Username [$destVCUsername]"
    if ([string]::IsNullOrWhiteSpace($string_destVCUsername)) { $string_destVCUsername = $destVCUsername }

    $string_destVCPassword = read-host -assecurestring "Enter the destination vCenters Password [********]"
    if ([string]::IsNullOrWhiteSpace($string_destVCPassword)) { $string_destVCPassword = $destVCPassword }
    
    $destVCCredential=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $string_destVCUsername, $string_destVCPassword
}



$sourceVC_result = Connect-VIServer -Server $string_sourceVC -Credential $sourceVCCredential
WriteLogScreen "Source Connected     : $($sourceVC_result.name) `tUser: $($sourceVC_result.user) `tVersion: $($sourceVC_result.version)"

$destVC_result = Connect-VIServer -Server $string_destVC -Credential $destVCCredential
WriteLogScreen "Destination Connected: $($destVC_result.name) `tUser: $($destVC_result.user) `tVersion: $($destVC_result.version)"

if ([string]::IsNullOrWhiteSpace($($global:DefaultVIServers[1].name))) { WriteLogScreen "`nERROR: Not connected to source vCenter... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit }
if ([string]::IsNullOrWhiteSpace($($global:DefaultVIServers[0].name))) { WriteLogScreen "`nERROR: Not connected to source vCenter... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit }
$sourceVC = $global:DefaultVIServers[1]
$destVC = $global:DefaultVIServers[0]
$destVCusername = $string_destVCUsername
$destVCpassword = $string_destVCPassword


#
#
#
#############################################################
### Select Source VM
#############################################################
WriteLogScreen "`nStep 3. Select Source VM"
$array_sourceVMs = get-vm -Server $($global:DefaultVIServers[1].name) | sort name
$FTarray_sourceVMs = @()
foreach ($vm in $array_sourceVMs) {
    $VM_datastores = get-datastore -id $vm.DatastoreIdList
    $VM_networks = Get-NetworkAdapter $vm | select-object networkname
    $FT_sourceVM = New-Object psobject
    $FT_sourceVM  | Add-Member -type NoteProperty -name Idx -Value "$($array_sourceVMs.indexof($vm))."
    $FT_sourceVM  | Add-Member -type NoteProperty -name Name -Value $($vm.Name)
    $FT_sourceVM  | Add-Member -type NoteProperty -name Folder -Value $($vm.Folder)
    $FT_sourceVM  | Add-Member -type NoteProperty -name Host -Value $($vm.VMHost.name)
    $FT_sourceVM  | Add-Member -type NoteProperty -name Cluster -Value (get-cluster -vmhost $($vm.VMHost)).name
    $FT_sourceVM  | Add-Member -type NoteProperty -name ResourcePool -Value $($vm.ResourcePool.Name)
    $FT_sourceVM  | Add-Member -type NoteProperty -name PowerState -Value $($vm.PowerState)
    $FT_sourceVM  | Add-Member -type NoteProperty -name Datastores -Value $VM_datastores
    $FT_sourceVM  | Add-Member -type NoteProperty -name Networks -Value $VM_networks.networkname
    $FT_sourceVM  | Add-Member -type NoteProperty -name NumCPU -Value $($vm.NumCpu)
    $FT_sourceVM  | Add-Member -type NoteProperty -name MemoryGB -Value $($vm.MemoryGB)
    $FTarray_sourceVMs += $FT_sourceVM
}
$FTarray_sourceVMs | select idx, name, folder, powerstate, datastores, networks, numcpu, memorygb | format-table 
$string_sourceVMs = read-host -Prompt "`nEnter the source VM idx number, use space as seperator for multiple entries"

$FTarray_selected_sourceVMs = @()
$FTstring_selected_sourceVMs = ""
foreach ($vm in $string_sourceVMs.split(" ")) { 
    $FTstring_selected_sourceVMs += $FTarray_sourceVMs[$vm].name + " "

    ### Built array with workload migration
    $FT_selected_sourceVM = New-Object psobject
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name SourceVM -Value $FTarray_sourceVMs[$vm].name
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name Powerstate -Value $FTarray_sourceVMs[$vm].PowerState
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name SourcevCenter -Value $string_sourceVC
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name SourceCluster -Value $FTarray_sourceVMs[$vm].Cluster
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name SourceHost -Value $FTarray_sourceVMs[$vm].Host
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name SourcePool -Value $FTarray_sourceVMs[$vm].ResourcePool
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name SourceDatastore -Value $FTarray_sourceVMs[$vm].Datastores
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name SourceNetwork -Value $FTarray_sourceVMs[$vm].Networks
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name DestvCenter -Value $string_destVC
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name DestCluster -Value NotSet
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name DestHost -Value NotSet
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name DestPool -Value NotSet
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name DestDatastore -Value NotSet
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name DestNetwork -Value NotSet
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name DestSwitch -Value NotSet
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name DestSwitchType -Value NotSet
    $FT_selected_sourceVM | Add-Member -type NoteProperty -name ComputeXVCOnly -Value NotSet
    $FTarray_selected_sourceVMs += $FT_selected_sourceVM
}
$FTstring_selected_sourceVMs = $FTstring_selected_sourceVMs.Trim()

#
#
#
#############################################################
### Select Destination Host & Cluster
#############################################################
WriteLogScreen "`nStep 4. Select destination Host & Cluster for selected VM's [$($FTstring_selected_sourceVMs)]"
$array_destHost = get-vmhost -Server $($global:DefaultVIServers[0].name) | where-object { $_.ConnectionState -eq "Connected"} | sort Parent, name
$FTarray_destHost = @()
foreach ($vmhost in $array_destHost) {
    $FT_destHost = New-Object psobject
    $FT_destHost  | Add-Member -type NoteProperty -name Idx -Value "$($array_destHost.indexof($vmhost))."
    $FT_destHost  | Add-Member -type NoteProperty -name Name -Value $($vmhost.Name)
    $FT_destHost  | Add-Member -type NoteProperty -name Cluster -Value (get-cluster -vmhost $($vmhost.name)).name
    $FT_destHost  | Add-Member -type NoteProperty -name Model -Value $($vmhost.Model)
    $FT_destHost  | Add-Member -type NoteProperty -name Processor -Value "$($vmhost.NumCpu)x $($vmhost.ProcessorType)"
    $FT_destHost  | Add-Member -type NoteProperty -name CpuTotalMhz -Value $($vmhost.CpuTotalMhz)
    $FT_destHost  | Add-Member -type NoteProperty -name CpuUsageMhz -Value $($vmhost.CpuUsageMhz)
    $FT_destHost  | Add-Member -type NoteProperty -name MemoryTotalGB -Value $([math]::Round($vmhost.MemoryTotalGB))
    $FT_destHost  | Add-Member -type NoteProperty -name MemoryUsageGB -Value $([math]::Round($vmhost.MemoryUsageGB))
    $FT_destHost  | Add-Member -type NoteProperty -name Version -Value "$($vmhost.Version) $($vmhost.Build)"
    $FT_destHost  | Add-Member -type NoteProperty -name MaxEVCMode -Value $($vmhost.MaxEVCMode)
    $FTarray_destHost += $FT_destHost
}
$FTarray_destHost | format-table 
$string_destHost = read-host -Prompt "`nEnter the destination host idx number, single entry only [$vmhostname]"
if ([string]::IsNullOrWhiteSpace($string_destHost)) { 
    $FTstring_selected_destHost = $vmhostname
} elseif ( ($string_destHost -notcontains " ") -and ($FTarray_destHost[$string_destHost].Name) ) {
    $FTstring_selected_destHost = $FTarray_destHost[$string_destHost].Name
} else {
    WriteLogScreen "`nERROR: Incorrect host selected... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit
}
if (!(get-vmhost -Server $($global:DefaultVIServers[0].name) -Name "$($FTstring_selected_destHost)" -ErrorAction SilentlyContinue)) { WriteLogScreen "`nERROR: Incorrect host selected... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit }

### Add Host & Cluster to array with workload migration
foreach ($vm in $FTarray_selected_sourceVMs) {
    $index = $($FTarray_selected_sourceVMs.IndexOf($vm))
    $FTarray_selected_sourceVMs[$index].DestCluster = (get-cluster -vmhost $($FTstring_selected_destHost)).name
    $FTarray_selected_sourceVMs[$index].DestHost = $FTstring_selected_destHost
}


#
#
#
#############################################################
### Select Destination Resource Pool
#############################################################
WriteLogScreen "`nStep 5. Select destination resource pool for selected VM's [$($FTstring_selected_sourceVMs)]"
$array_destRP = get-resourcepool -Server $($global:DefaultVIServers[0].name) -Location (get-cluster -vmhost $($FTstring_selected_destHost)).name
$FTarray_destRP = @()
foreach ($rp in $array_destRP) {
    $FT_destRP = New-Object psobject
    $FT_destRP  | Add-Member -type NoteProperty -name Idx -Value "$($array_destRP.indexof($rp))."
    $FT_destRP  | Add-Member -type NoteProperty -name Name -Value $($rp.Name)
    $FT_destRP  | Add-Member -type NoteProperty -name CpuSharesLevel -Value $($rp.CpuSharesLevel)
    $FT_destRP  | Add-Member -type NoteProperty -name NumCpuShares -Value $($rp.NumCpuShares)
    $FT_destRP  | Add-Member -type NoteProperty -name CpuReservationMHz -Value $($rp.CpuReservationMHz)
    $FT_destRP  | Add-Member -type NoteProperty -name MemSharesLevel -Value $($rp.MemSharesLevel)
    $FT_destRP  | Add-Member -type NoteProperty -name NumMemShares -Value $($rp.ParentFolder)
    $FT_destRP  | Add-Member -type NoteProperty -name MemReservationGiB -Value $([math]::Round($rp.MemReservationGB,1))
    $FT_destRP  | Add-Member -type NoteProperty -name Parent -Value $($rp.Parent)
    $FTarray_destRP += $FT_destRP
}
$FTarray_destRP | format-table 
$string_destRP = read-host -Prompt "`nEnter the destination resource pool idx number, single entry only [$resourcepool]"
if ([string]::IsNullOrWhiteSpace($string_destRP)) { 
    $FTstring_selected_destRP = $resourcepool
} elseif ( ($string_destRP -notcontains " ") -and ($FTarray_destRP[$string_destRP].Name) ) {
    $FTstring_selected_destRP = $FTarray_destRP[$string_destRP].Name
} else {
    WriteLogScreen "`nERROR: Incorrect resource pool selected... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit
}
if (!(get-resourcepool -Server $($global:DefaultVIServers[0].name) -Name "$($FTstring_selected_destRP)" -ErrorAction SilentlyContinue)) { WriteLogScreen "`nERROR: Incorrect resource pool selected... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit }

### Add Resource Pool to array with workload migration
foreach ($vm in $FTarray_selected_sourceVMs) {
    $index = $($FTarray_selected_sourceVMs.IndexOf($vm))
    $FTarray_selected_sourceVMs[$index].DestPool = $FTstring_selected_destRP
}



#
#
#
#############################################################
### Select Destination Datastore
#############################################################
WriteLogScreen "`nStep 6. Select destination datastore for selected VM's [$($FTstring_selected_sourceVMs)]"
$array_destDS = get-datastore -Server $($global:DefaultVIServers[0].name) -id (get-vmhost -name "$FTstring_selected_destHost").DatastoreIdList | sort Datacenter, ParentFolder, Name
$FTarray_destDS = @()
foreach ($ds in $array_destDS) {
    $FT_destDS = New-Object psobject
    $FT_destDS  | Add-Member -type NoteProperty -name Idx -Value "$($array_destDS.indexof($ds))."
    $FT_destDS  | Add-Member -type NoteProperty -name Name -Value $($ds.Name)
    $FT_destDS  | Add-Member -type NoteProperty -name FreeSpaceGiB -Value $([math]::Round($ds.FreeSpaceGB,1))
    $FT_destDS  | Add-Member -type NoteProperty -name CapacityGiB -Value $([math]::Round($ds.CapacityGB,1))
    $FT_destDS  | Add-Member -type NoteProperty -name Datacenter -Value $($ds.Datacenter)
    $FT_destDS  | Add-Member -type NoteProperty -name Folder -Value $($ds.ParentFolder)
    $FT_destDS  | Add-Member -type NoteProperty -name Type -Value $($ds.Type)
    $FTarray_destDS += $FT_destDS
}
$FTarray_destDS | format-table 
$string_destDS = read-host -Prompt "`nEnter the destination datastore idx number, single entry only [$datastorename]"
if ([string]::IsNullOrWhiteSpace($string_destDS)) { 
    $FTstring_selected_destDS = $datastorename 
} elseif ( ($string_destDS -notcontains " ") -and ($FTarray_destDS[$string_destDS].Name) ) {
    $FTstring_selected_destDS = $FTarray_destDS[$string_destDS].Name
} else {
    WriteLogScreen "`nERROR: Incorrect datastore selected... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit
}
if (!(get-datastore -Server $($global:DefaultVIServers[0].name) -Name "$($FTstring_selected_destDS)" -ErrorAction SilentlyContinue)) { WriteLogScreen "`nERROR: Incorrect datastore selected... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit }

### Add Datastore to array with workload migration
foreach ($vm in $FTarray_selected_sourceVMs) {
    $index = $($FTarray_selected_sourceVMs.IndexOf($vm))
    $FTarray_selected_sourceVMs[$index].DestDatastore = $FTstring_selected_destDS
    if ($FTarray_sourceVMs.Name.IndexOf($vm).Datastores -contains $FTstring_selected_destDS) { 
        $FTarray_selected_sourceVMs[$index].ComputeXVCOnly = 1
    } else {
        $FTarray_selected_sourceVMs[$index].ComputeXVCOnly = 0
    }
}


#
#
#
#############################################################
### Select Destination Network
#############################################################
WriteLogScreen "`nStep 7. Select destination network for selected VM's [$($FTstring_selected_sourceVMs)]"
$array_destPG_vSwitch = get-virtualportgroup -standard -Server $($global:DefaultVIServers[0].name) -VMHost $FTstring_selected_destHost | sort virtualswitch, name
$array_destPG_dvSwitch = get-virtualportgroup -distributed -Server $($global:DefaultVIServers[0].name) -VMHost $FTstring_selected_destHost | sort virtualswitch, name
$array_destPG_dvSwitch = $array_destPG_dvSwitch | where-object { !(get-virtualswitch -name $_.VirtualSwitch).ExtensionData.config.Uplinkportgroup.value.contains($_.key) }
$array_destPG = $array_destPG_vSwitch + $array_destPG_dvSwitch | sort virtualswitch, name
$FTarray_destPG = @()
foreach ($pg in $array_destPG) {
    if ($pg.Extensiondata.Config.DefaultPortCOnfig.Vlan.VlanId) {
        $pg_type = "dvSwitch"
        $pg_vlan = $pg.Extensiondata.Config.DefaultPortCOnfig.Vlan.VlanId
    } else {
        $pg_type = "vSwitch"
        $pg_vlan = $pg.vlanid
    } 
    $FT_destPG = New-Object psobject
    $FT_destPG  | Add-Member -type NoteProperty -name Idx -Value "$($array_destPG.indexof($pg))."
    $FT_destPG  | Add-Member -type NoteProperty -name Name -Value $($pg.Name)
    $FT_destPG  | Add-Member -type NoteProperty -name VlanID -Value $($pg_vlan)
    $FT_destPG  | Add-Member -type NoteProperty -name VirtualSwitch -Value $($pg.VirtualSwitch)
    $FT_destPG  | Add-Member -type NoteProperty -name Type -Value $($pg_type)
    $FTarray_destPG += $FT_destPG
}
$FTarray_destPG | format-table 
#$FTarray_selected_destPG = @()
foreach ($vm in $FTarray_selected_sourceVMs) {
    $vm = $vm.SourceVM
    $nic = ""
    $vm_nics = $()
    $FTarray_nics = get-networkadapter $vm
    foreach ($nic in $FTarray_nics) { $vm_nics += "[" + $($nic.networkname) + "]" + " " }
    WriteLogScreen "`n$($FTarray_selected_sourceVMs.SourceVM.indexof($vm)). For $VM with networks: $($vm_nics.trim())"
    $nic_count = $FTarray_nics.count
    if ($nic_count -eq 0) { 
        WriteLogScreen "`nWarning: no network found on this VM"
        $string_destPG = "EMPTY"
    } elseif ($nic_count -eq 1) { 
        $string_destPG = read-host -Prompt "$($FTarray_selected_sourceVMs.SourceVM.indexof($vm)). Enter the destination network idx number, single entry only [$vmnetworkname]"
        if ([string]::IsNullOrWhiteSpace($string_destPG)) { 
            $string_destPG = $vmnetworkname 
        } elseif ( ($string_destPG -notcontains " ") -and ($FTarray_destPG[$string_destPG].Name) ) {
           # OK, do nothing
        } else {
            WriteLogScreen "`nERROR: Incorrect portgroup(s) selected... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit
        }
    } else {
        $string_destPG = read-host -Prompt "$($FTarray_selected_sourceVMs.SourceVM.indexof($vm)). Enter the destination network idx number, use space as seperator for these $nic_count entries, in the correct order"
        $exist_destPG = $true
        foreach ($pg in $string_destPG.split(" ")) { if (!($FTarray_destPG.Idx.Contains("$($pg)."))) { $exist_destPG = $false } }
        if (!($string_destPG.split(" ").count -eq $nic_count)) { $exist_destPG = $false }
        if ($exist_destPG) {
            # OK, do nothing
        } else {
            WriteLogScreen "`nERROR: Incorrect portgroup(s) selected... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit
        }

    }

    ### Add Network config to array with workload migration
    $index = $($FTarray_selected_sourceVMs.sourceVM.IndexOf($vm))

    $string_destPG_names = ""
    foreach ($pg in $string_destPG.split(" ")) { $string_destPG_names += $FTarray_destPG[$pg].name + "," }
    $string_destPG_names = $string_destPG_names.TrimEnd(',')
    $FTarray_selected_sourceVMs[$index].DestNetwork = $string_destPG_names
    $FTarray_selected_sourceVMs[$index].DestSwitch = $FTarray_destPG[$($string_destPG.split(" ")[0])].VirtualSwitch.Name
    $FTarray_selected_sourceVMs[$index].DestSwitchType = $FTarray_destPG[$($string_destPG.split(" ")[0])].Type
    
}


##### Array with workload migration
foreach ($selected_vm in $FTarray_selected_sourceVMs) {

    writelogscreen "`n$($selected_vm.sourcevm)" 
    writelogscreen "------------------------------------------------                                ------------------------------------------------                                "
    writelogscreen "Source                                                                          Destination"
    writelogscreen "------------------------------------------------                                ------------------------------------------------                                "

    $textA = [string]$($selected_vm.sourcevcenter)
    $textA = $textA.substring(0, [System.Math]::Min(59, $textA.Length))
    $textB = [string]$($selected_vm.destvcenter)
    $textB = $textB.substring(0, [System.Math]::Min(59, $textB.Length))
    $fillspaces = " " * (80 - 18 - $textA.Length)     
    writelogscreen "SourcevCenter   : $textA$($fillspaces)DestvCenter   : $textB"

    $textA = [string]$($selected_vm.SourceCluster)
    $textA = $textA.substring(0, [System.Math]::Min(59, $textA.Length))
    $textB = [string]$($selected_vm.destcluster)
    $textB = $textB.substring(0, [System.Math]::Min(59, $textB.Length))
    $fillspaces = " " * (80 - 18 - $textA.Length) 
    writelogscreen "SourceCluster   : $textA$($fillspaces)DestCluster   : $textB"

    $textA = [string]$($selected_vm.SourceHost)
    $textA = $textA.substring(0, [System.Math]::Min(59, $textA.Length))
    $textB = [string]$($selected_vm.desthost)
    $textB = $textB.substring(0, [System.Math]::Min(59, $textB.Length))
    $fillspaces = " " * (80 - 18 - $textA.Length) 
    writelogscreen "SourceHost      : $textA$($fillspaces)DestHost      : $textB"

    $textA = [string]$($selected_vm.SourcePool)
    $textA = $textA.substring(0, [System.Math]::Min(59, $textA.Length))
    $textB = [string]$($selected_vm.destPool)
    $textB = $textB.substring(0, [System.Math]::Min(59, $textB.Length))
    $fillspaces = " " * (80 - 18 - $textA.Length) 
    writelogscreen "SourcePool      : $textA$($fillspaces)DestPool      : $textB"

    $textA = [string]$($selected_vm.SourceDatastore.Name)
    $textA = $textA.substring(0, [System.Math]::Min(59, $textA.Length))
    $textB = [string]$($selected_vm.destDatastore)
    $textB = $textB.substring(0, [System.Math]::Min(59, $textB.Length))
    $fillspaces = " " * (80 - 18 - $textA.Length) 
    writelogscreen "SourceDatastore : $textA$($fillspaces)DestDatastore : $textB"
    
    $textA = [string]$($selected_vm.SourceNetwork)
    $textA = $textA.substring(0, [System.Math]::Min(59, $textA.Length))
    $textB = [string]$($selected_vm.destNetwork)
    $textB = $textB.substring(0, [System.Math]::Min(59, $textB.Length))
    $fillspaces = " " * (80 - 18 - $textA.Length) 
    writelogscreen "SourceNetwork   : $textA$($fillspaces)DestNetwork   : $textB"
}

##### Final check question
write-host "`n"
$final_check = read-host -Prompt "Are these correct? Start the (E)xVC-vMotions? [Y/N]"
if ( $final_check -ieq "Y" ) { 
    # do nothing, continue
} else {
    WriteLogScreen "`nERROR: Stopped... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit
}


##### (E)xVC-vMotion parallel start
foreach ($selected_vm in $FTarray_selected_sourceVMs) {

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($destVCpassword)
    $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    xMove-VM  -vm $selected_vm.sourcevm `
     -sourcevc $sourceVC `
     -destvc $destVC `
     -destVCusername $destVCusername `
     -destVCpassword $UnsecurePassword `
     -switchtype $selected_vm.DestSwitchType `
     -resourcepool $selected_vm.DestPool `     -datastore $selected_vm.DestDatastore `
     -vmhost $selected_vm.DestHost `
     -xvctype $selected_vm.ComputeXVCOnly `
     -vmnetworks $selected_vm.DestNetwork `
     -cluster $selected_vm.DestCluster `
     -uppercaseuuid $true

     $UnsecurePassword = ""
}


##### (E)xVC-vMotion progress bar
$totalpercent = 0
While ($totalpercent -ne 100) {
    $tasks = get-task | where-object { $_.name -eq "RelocateVM_Task" }
    if ([string]::IsNullOrWhiteSpace($tasks)) { 
        $totalpercent = 100 
    } else {
        $avg=0
        foreach ($task in $tasks) {$avg+=$task.PercentComplete}
        $totalpercent = $([math]::Round($($avg/($tasks.count)),0))

        write-progress -Activity "Total (E)xVC-vMotions - $($tasks.Count) VM(s) - $($totalpercent)%" -PercentComplete $totalpercent -id 1
        
        $id_child=2
        foreach ($task in $tasks) {
            write-progress -Activity "VM: $($task.extensiondata.info.EntityName)" -Status "Starttime: $($task.StartTime) - $($task.State) - $($task.PercentComplete)%" -PercentComplete $($task.PercentComplete) -id $id_child -ParentId 1
            $id_child ++
        }
    }
    sleep 1 
} 

