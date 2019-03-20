<#
.SYNOPSIS
   (E)xVC-vMotion Helper
   This script gives the PowerCLI function move-vm:
   - a wizard driven workflow to easily select the workloads to migrate.
   - a fast cli based way to migrate with some autodetect features (networking) and built-in safety checks.

   Previous versions were based on xMove-VM from xMove-VM.ps1 1.2 written by William Lam

   Offcourse it CAN use the same inputs on commandline, but without gives you a nice wizard to walk you through every step including the selection of every source en destination parameter needed for the move.
   
   With the move-vm we can do an xVC-vMotion where a running Virtual Machine
   is live migrated between two vCenter Servers which are NOT part of the
   same SSO Domain which is only available using the vSphere 6.0 API.

   This script also supports live migrating a running Virtual Machine between
   two vCenter Servers that ARE part of the same SSO Domain (aka Enhanced Linked Mode)

   This script also supports migrating VMs connected to both a VSS/VDS as well as having multiple vNICs

   This script also supports migrating to/from VMware Cloud on AWS (VMC)

   When using different version of vDS, it can be helpful to set the advanced setting:
   "config.migrate.test.NetworksCompatibleOption.AllowMismatchedDVSwitchConfig" to "true" on vCenter level.
   You must be running vSphere 6.0 Update 3, vSphere 6.5 Update 2 and vSphere 6.7+ and customers with NSX-V, 
   you will need to be running at least NSX-V 6.3.6 or greater for your onPrem vCenter Server (includes ESXi host version)
   https://www.virtuallyghetto.com/2018/09/vmotion-across-different-vds-version-between-onprem-and-vmc.html
.NOTES
   ================================
   name     : (E)xVC-vMotion Helper
   filename : ExVC-vMotion-Helper.ps1
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
   https://www.virtuallyghetto.com/2018/09/vmotion-across-different-vds-version-between-onprem-and-vmc.html
.LINK
   https://github.com/lamw
.INPUTS
   PsourceVM, PsourceVC, PsourceVCUsername, PsourceVCPassword, PdestVC, PdestVCUsername, PdestVCpassword,
   Pdestdatastorename, Pdestresourcepool, Pdestvmhostname, Pdestswitchname, Pnetworkautodetect, Confirm

   Not yet implemented:
   Pdestvmnetworkname1, Pdestvmnetworkname2, Pdestvmnetworkname3, Pdestvmnetworkname4, Pdestvmnetworkname5, 
   Pdestvmnetworkname6, Pdestvmnetworkname7, Pdestvmnetworkname8, Pdestvmnetworkname9, Pdestvmnetworkname10
.OUTPUTS
   Console output
#>


param(
  [Parameter(Mandatory=$false)]
  [string] $PsourceVM,
  [Parameter(Mandatory=$false)]
  [string] $PsourceVC,
  [Parameter(Mandatory=$false)]
  [string] $PsourceVCUsername,
  [Parameter(Mandatory=$false)]
  [string] $PsourceVCPassword,
  [Parameter(Mandatory=$false)]
  [string] $PdestVC,
  [Parameter(Mandatory=$false)]
  [string] $PdestVCUsername,
  [Parameter(Mandatory=$false)]
  [string] $PdestVCpassword,
  [Parameter(Mandatory=$false)]
  [string] $Pdestdatastorename,
  [Parameter(Mandatory=$false)]
  [string] $Pdestresourcepool,
  [Parameter(Mandatory=$false)]
  [string] $Pdestvmhostname,
  [Parameter(Mandatory=$false)]
  [string] $Pdestvmnetworkname1,
  [Parameter(Mandatory=$false)]
  [string] $Pdestvmnetworkname2,
  [Parameter(Mandatory=$false)]
  [string] $Pdestvmnetworkname3,
  [Parameter(Mandatory=$false)]
  [string] $Pdestvmnetworkname4,
  [Parameter(Mandatory=$false)]
  [string] $Pdestvmnetworkname5,
  [Parameter(Mandatory=$false)]
  [string] $Pdestvmnetworkname6,
  [Parameter(Mandatory=$false)]
  [string] $Pdestvmnetworkname7,
  [Parameter(Mandatory=$false)]
  [string] $Pdestvmnetworkname8,
  [Parameter(Mandatory=$false)]
  [string] $Pdestvmnetworkname9,
  [Parameter(Mandatory=$false)]
  [string] $Pdestvmnetworkname10,
  [Parameter(Mandatory=$false)]
  [string] $Pdestswitchname,
  [Parameter(Mandatory=$false)]
  [switch] $Pnetworkautodetect,
  [Parameter(Mandatory=$false)]
  [boolean] $Confirm

)

### VARS DONT TOUCH
$version = "v2.1"
### VARS

# Variables that can be defined as defaults
$sourceVM = "VM-1"
$sourceVC = "vcenter60-1.primp-industries.com"
$sourceVCUsername = "administrator@vghetto.local"
$sourceVCPassword = "VMware1!"
$destVC = "vcenter60-3.primp-industries.com"
$destVCUsername = "administrator@vghetto.local"
$destVCpassword = "VMware1!"
$destdatastorename = "la-datastore1"
$destresourcepool = "WorkloadRP"
$destvmhostname = "vesxi60-5.primp-industries.com"
$destvmnetworkname1 = "LA-VM-Network1"
$destvmnetworkname2 = "LA-VM-Network2"
$destvmnetworkname3 = "LA-VM-Network3"
$destvmnetworkname4 = "LA-VM-Network4"
$destswitchname = "LA-VDS"
#$destswitchtype = "vds" (autodetect)

$Confirm = $False
$doReport = $True # Option to report/mail
$logfile = "ExVC-vMotion-Helper.log"
if ($doReport) { 
    if ([System.IO.File]::Exists($logfile)) { Clear-Content $logfile }
}



##### WriteLogScreen
function WriteLogScreen {
   Param ([string]$logstring)
   if ($doReport) { $logstring | out-file -Filepath $logfile -append }
   write-host "$logstring" -Fore DarkGray
}

if (($Pdestvmnetworkname1) -or ($Pdestvmnetworkname2) -or ($Pdestvmnetworkname3) -or ($Pdestvmnetworkname4) -or ($Pdestvmnetworkname5) -or ($Pdestvmnetworkname6) -or ($Pdestvmnetworkname7) -or ($Pdestvmnetworkname8) -or ($Pdestvmnetworkname9) -or ($Pdestvmnetworkname10) -or ($Pdestswitchname)) {
  WriteLogScreen "`nERROR: -PdestvmnetworknameX not yet implemented... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit
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

if ($PsourceVC) { $string_sourceVC = $PsourceVC }
else {
  $string_sourceVC = read-host -Prompt "Enter the source vCenters FQDN [$sourceVC]"
  if ([string]::IsNullOrWhiteSpace($string_sourceVC)) { $string_sourceVC = $sourceVC }
}

if ($PsourceVCUsername) { $string_sourceVCUsername = $PsourceVCUsername }
else {
  $string_sourceVCUsername = read-host -Prompt "Enter the source vCenters Username [$sourceVCUsername]"
  if ([string]::IsNullOrWhiteSpace($string_sourceVCUsername)) { $string_sourceVCUsername = $sourceVCUsername }
}

if ($PsourceVCPassword) { $string_sourceVCPassword = ConvertTo-SecureString -String $PsourceVCPassword -AsPlainText -Force }
else {
  $string_sourceVCPassword = read-host -assecurestring "Enter the source vCenters Password [********]"
  if ([string]::IsNullOrWhiteSpace($string_sourceVCPassword)) { $string_sourceVCPassword = $sourceVCPassword }
}

$sourceVCCredential=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $string_sourceVCUsername, $string_sourceVCPassword


#
#
#
#############################################################
### Destination vCenter
#############################################################
WriteLogScreen "`nStep 2. Destination vCenter"

if ($PdestVC) { $string_destVC = $PdestVC }
else {
  $string_destVC = read-host -Prompt "Enter the destination vCenters FQDN [$destVC]"
  if ([string]::IsNullOrWhiteSpace($string_destVC)) { $string_destVC = $destVC }
}

if (($PdestVCUsername) -and ($PdestVCPassword)) {
  $string_destVCUsername = $PdestVCUsername
  $string_destVCPassword = ConvertTo-SecureString -String $PdestVCPassword -AsPlainText -Force
  $destVCCredential=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $string_destVCUsername, $string_destVCPassword
}
else {
  $string_destcredresuse = read-host -Prompt "Use the same credentials for the destination vCenter? [Y/N]"
  if ( $string_destcredresuse -ieq "Y" ) { 
      $string_destVCUsername = $string_sourceVCUsername
      $string_destVCPassword = $string_sourceVCPassword
      $destVCCredential = $sourceVCCredential
  } else {
      if ($PdestVCUsername) { $string_destVCUsername = $PdestVCUsername }
      else {
        $string_destVCUsername = read-host -Prompt "Enter the destination vCenters Username [$destVCUsername]"
        if ([string]::IsNullOrWhiteSpace($string_destVCUsername)) { $string_destVCUsername = $destVCUsername }
      }

      if ($PdestVCPassword) { $string_destVCPassword = ConvertTo-SecureString -String $PdestVCPassword -AsPlainText -Force }
      else {
        $string_destVCPassword = read-host -assecurestring "Enter the destination vCenters Password [********]"
        if ([string]::IsNullOrWhiteSpace($string_destVCPassword)) { $string_destVCPassword = $destVCPassword }
      }

      $destVCCredential=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $string_destVCUsername, $string_destVCPassword
  }
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
$array_sourceVMs = @()
if ($PsourceVM) { 
  $string_sourceVM = $PsourceVM 
  $array_sourceVMs += get-vm -Server $($global:DefaultVIServers[1].name) -Name $string_sourceVM | sort name
} else {
  $array_sourceVMs += get-vm -Server $($global:DefaultVIServers[1].name) | sort name
}
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

if ($PsourceVM) { 
  [string] $string_sourceVMs = $($array_sourceVMs.Name.indexof($string_sourceVM))
}
else {
  $FTarray_sourceVMs | select idx, name, folder, powerstate, datastores, networks, numcpu, memorygb | format-table 
  $string_sourceVMs = read-host -Prompt "`nEnter the source VM idx number, use space as seperator for multiple entries"
}

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
$array_destHost = @()
if ($Pdestvmhostname) { 
  $string_destvmhostname = $Pdestvmhostname 
  $array_destHost += get-vmhost -Server $($global:DefaultVIServers[0].name) -name $string_destvmhostname | where-object { $_.ConnectionState -eq "Connected"} | sort Parent, name
} else {
  $array_destHost += get-vmhost -Server $($global:DefaultVIServers[0].name) | where-object { $_.ConnectionState -eq "Connected"} | sort Parent, name
}
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
if ($Pdestvmhostname) { 
  [string] $string_destHost = $($array_destHost.Name.indexof($string_destvmhostname))
}
else {
  $FTarray_destHost | format-table 
  $string_destHost = read-host -Prompt "`nEnter the destination host idx number, single entry only [$vmhostname]"
}
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
$array_destRP = @()
if ($Pdestresourcepool) { 
  $string_destRP = $Pdestresourcepool 
  $array_destRP += get-resourcepool -Server $($global:DefaultVIServers[0].name) -Location (get-cluster -vmhost $($FTstring_selected_destHost)).name -Name $string_destRP
} else {
  $array_destRP += get-resourcepool -Server $($global:DefaultVIServers[0].name) -Location (get-cluster -vmhost $($FTstring_selected_destHost)).name 
}


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

if ($Pdestresourcepool) { 
  [string] $string_destRP = $($array_destRP.Name.indexof($string_destRP))
  if ($string_destRP -eq "-1") { $string_destRP = "" }
} else {
  $FTarray_destRP | format-table 
  $string_destRP = read-host -Prompt "`nEnter the destination resource pool idx number, single entry only [$destresourcepool]"
}
if ([string]::IsNullOrWhiteSpace($string_destRP)) { 
    $FTstring_selected_destRP = $destresourcepool
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
$array_destDS = @()
if ($Pdestdatastorename) { 
  $string_destDS = $Pdestdatastorename 
  $array_destDS += get-datastore -Server $($global:DefaultVIServers[0].name) -id (get-vmhost -name "$FTstring_selected_destHost").DatastoreIdList | sort Datacenter, ParentFolder, Name
} else {
  $array_destDS += get-datastore -Server $($global:DefaultVIServers[0].name) -id (get-vmhost -name "$FTstring_selected_destHost").DatastoreIdList | sort Datacenter, ParentFolder, Name
}
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
if ($Pdestdatastorename) { 
  [string] $string_destDS = $($array_destDS.Name.indexof($string_destDS))
  if ($string_destDS -eq "-1") { $string_destDS = "" }
} else {
  $FTarray_destDS | format-table 
  $string_destDS = read-host -Prompt "`nEnter the destination datastore idx number, single entry only [$datastorename]"
}
if ([string]::IsNullOrWhiteSpace($string_destDS)) { 
    $FTstring_selected_destDS = $destdatastorename 
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
}


#
#
#
#############################################################
### Select Destination Network
#############################################################
WriteLogScreen "`nStep 7. Select destination network for selected VM's [$($FTstring_selected_sourceVMs)]"

#Source PG Array
$FTstring_selected_sourceHost = get-vmhost -Server $($global:DefaultVIServers[1].name) -VM $($FTstring_selected_sourceVMs)
$array_sourcePG_vSwitch = get-virtualportgroup -standard -Server $($global:DefaultVIServers[1].name) -VMHost $FTstring_selected_sourceHost | sort virtualswitch, name
$array_sourcePG_dvSwitch = get-virtualportgroup -distributed -Server $($global:DefaultVIServers[1].name) -VMHost $FTstring_selected_sourceHost | sort virtualswitch, name
$array_sourcePG_dvSwitch = $array_sourcePG_dvSwitch | where-object { !(get-virtualswitch -name $_.VirtualSwitch).ExtensionData.config.Uplinkportgroup.value.contains($_.key) }
$array_sourcePG = $array_sourcePG_vSwitch + $array_sourcePG_dvSwitch | sort virtualswitch, name
$FTarray_sourcePG = @()
foreach ($pg in $array_sourcePG) {
    if ($pg.Extensiondata.Config.DefaultPortCOnfig.Vlan.VlanId) {
        $pg_type = "dvSwitch"
        $pg_vlan = $pg.Extensiondata.Config.DefaultPortCOnfig.Vlan.VlanId
    } else {
        $pg_type = "vSwitch"
        $pg_vlan = $pg.vlanid
    } 
    $FT_sourcePG = New-Object psobject
    $FT_sourcePG  | Add-Member -type NoteProperty -name Idx -Value "$($array_sourcePG.indexof($pg))."
    $FT_sourcePG  | Add-Member -type NoteProperty -name Name -Value $($pg.Name)
    $FT_sourcePG  | Add-Member -type NoteProperty -name VlanID -Value $($pg_vlan)
    $FT_sourcePG  | Add-Member -type NoteProperty -name VirtualSwitch -Value $($pg.VirtualSwitch)
    $FT_sourcePG  | Add-Member -type NoteProperty -name Type -Value $($pg_type)
    $FTarray_sourcePG += $FT_sourcePG
}
#Dest PG Array
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

if ($Pnetworkautodetect) { 
  # nothing yet 
} else { 
  $FTarray_destPG | format-table 
}
$FTarray_nics = @()
foreach ($vm in $FTarray_selected_sourceVMs) {
    $vm = $vm.SourceVM
    $nic = ""
    $nicvlan = ""
    $vm_nics = $()
    $array_nics = @()
    $array_nics += get-networkadapter $vm
    foreach ($nic in $array_nics) { 
      $nicvlan = $FTarray_sourcePG[$FTarray_sourcePG.Name.IndexOf($nic.networkname)].vlanid
      $FTarray_nic = New-Object psobject
      $FTarray_nic  | Add-Member -type NoteProperty -name VM -Value $($vm)
      $FTarray_nic  | Add-Member -type NoteProperty -name Name -Value $($nic.networkname)
      $FTarray_nic  | Add-Member -type NoteProperty -name VlanID -Value $($nicvlan)
      $vm_nics += "[" + $($nic.networkname) + "," + $($nicvlan) + "]" + " " 
      $FTarray_nics +=$FTarray_nic
    }
    
    if ($Pnetworkautodetect) { 
      #Check if remote vlans all exist
      $string_destPG_names = ""
      foreach ($sourcepg in $FTarray_nics) {
        if ($sourcepg.vm -eq $vm) {
          if ($FTarray_destPG.vlanid.indexof($sourcepg.vlanid) -ge 0) {
            $destpgname = $FTarray_destPG[$FTarray_destPG.vlanid.indexof($sourcepg.vlanid)].name
            $string_destPG_names += $destpgname + " " 
          } else {
            WriteLogScreen "`nERROR: Portgroup with identical VlanID not found... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit
          }
        }
      }
      $string_destPG_names = $string_destPG_names.TrimEnd(' ')
      $FTarray_selected_sourceVMs[$index].DestNetwork = $string_destPG_names
    } else {
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
      foreach ($pg in $string_destPG.split(" ")) { $string_destPG_names += $FTarray_destPG[$pg].name + " " }
      $string_destPG_names = $string_destPG_names.TrimEnd(' ')
      $FTarray_selected_sourceVMs[$index].DestNetwork = $string_destPG_names
      $FTarray_selected_sourceVMs[$index].DestSwitch = $FTarray_destPG[$($string_destPG.split(" ")[0])].VirtualSwitch.Name
      $FTarray_selected_sourceVMs[$index].DestSwitchType = $FTarray_destPG[$($string_destPG.split(" ")[0])].Type
    }
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

if ($confirm -eq $false) {
    write-host "`n"
    $final_check = read-host -Prompt "Are these correct? Start the (E)xVC-vMotions? [Y/N]"
    if ( $final_check -ieq "Y" ) { 
        # do nothing, continue
    } else {
        WriteLogScreen "`nERROR: Stopped... Exiting..." ; $empty = Read-Host -Prompt 'Press enter to exit' ; exit
    }
} elsif ($confirm -eq $true) {
    # do nothing
}


##### (E)xVC-vMotion parallel start
foreach ($selected_vm in $FTarray_selected_sourceVMs) {

    #$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($destVCpassword)
    #$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    $destportgroups = @()
    $($selected_vm.DestNetwork)
    foreach ($destportgroup in $($selected_vm.DestNetwork).split(" ")) {
      $destportgroups += Get-VDPortgroup -Name $destportgroup -Server $destVC
    }

    Move-VM -VM (Get-VM -Server $sourceVC $($selected_vm.sourcevm)) `
     -VMotionPriority High `
     -runasync `
     -Destination (Get-VMhost -Server $destVC -Name $($selected_vm.DestHost)) `
     -Datastore (Get-Datastore -Server $destVC -Name $($selected_vm.DestDatastore)) `
     -NetworkAdapter (Get-NetworkAdapter -VM $vm -Server $sourceVC) `
     -PortGroup $destportgroups


#    xMove-VM  -vm $selected_vm.sourcevm `
#     -sourcevc $sourceVC `
#     -destvc $destVC `
#     -destVCusername $destVCusername `
#     -destVCpassword $UnsecurePassword `
#     -switchtype $selected_vm.DestSwitchType `
#     -resourcepool $selected_vm.DestPool `#     -datastore $selected_vm.DestDatastore `
#     -vmhost $selected_vm.DestHost `
#     -xvctype $selected_vm.ComputeXVCOnly `
#     -vmnetworks $selected_vm.DestNetwork `
#     -cluster $selected_vm.DestCluster `
#     -uppercaseuuid $true

     #$UnsecurePassword = ""
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

