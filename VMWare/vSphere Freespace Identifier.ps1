<#
.SYNOPSIS
   vSphere Freespace and UNMAP Identifier
   This script gives you the ability to check:
   A. For potential freespace hidden in VM's
   B. Check if automatic of manual UNMAP is activated or possible on the particular Virtual Machine.

   It outputs a powershell Grid and has the option to export to a CSV file.
   Includes vSAN support - impropoved/corrected vSAN support
.NOTES
   ================================
   name     : vSphere Freespace  and UNMAP Identifier
   filename : vSphere Freespace Identifier.ps1
   author   : Jan Jaap van Santen
   github   : janjaaps
   email    : janjaap@scict.nl
   blog     : https://scict.nl/
   ================================
.LINK
   https://scict.nl/vSphere-Freespace-Identifier
.LINK
   https://github.com/janjaaps
.INPUTS
   -vCenter #required
   -VMParam #optionel to check single VM, otherwise check all
   -ExportCSV <file.csv> #optional, instead of gridview
.OUTPUTS
   Gridview or CSV
#>

param(
  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string] $vCenter,
  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string] $Cluster,
  [Parameter(Mandatory=$true)]
  [AllowEmptyString()]
  [string] $VMparam,
  [Parameter(Mandatory=$false)]
  [string] $ExportCSV,
  [Parameter(Mandatory=$false)]
  [string] $ESXiHostUsername,
  [Parameter(Mandatory=$false)]
  [string] $ESXiHostPassword
)

### VARS DONT TOUCH
$version = "v1.1"
### VARS


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
write-host "`n/--------------------------------------------------------------------------------------------------------------------------------------------------------------\" 
write-host "|         __         _                            ___                                                    _____     _               _    _   __  _              |"
write-host "| __   __/ _\ _ __  | |__    ___  _ __  ___      / __\_ __  ___   ___  ___  _ __    __ _   ___  ___      \_   \ __| |  ___  _ __  | |_ (_) / _|(_)  ___  _ __  |"
write-host "| \ \ / /\ \ | '_ \ | '_ \  / _ \| '__|/ _ \    / _\ | '__|/ _ \ / _ \/ __|| '_ \  / _' | / __|/ _ \      / /\// _' | / _ \| '_ \ | __|| || |_ | | / _ \| '__| |"
write-host "|  \ V / _\ \| |_) || | | ||  __/| |  |  __/   / /   | |  |  __/|  __/\__ \| |_) || (_| || (__|  __/   /\/ /_ | (_| ||  __/| | | || |_ | ||  _|| ||  __/| |    |"
write-host "|   \_/  \__/| .__/ |_| |_| \___||_|   \___|   \/    |_|   \___| \___||___/| .__/  \__,_| \___|\___|   \____/  \__,_| \___||_| |_| \__||_||_|  |_| \___||_|    |"
write-host "|            |_|                                                           |_|                                                                            $version |"
write-host "\--------------------------------------------------------------------------------------------------------------------------------------------------------------/`n" 

Set-PowerCLIConfiguration -DisplayDeprecationWarnings $false -scope session -Confirm:$False | Out-Null
Set-PowerCLIConfiguration -InvalidCertificateAction warn -scope session -Confirm:$False | Out-Null
Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Scope Session -Confirm:$false | Out-Null
Disconnect-viserver * -Confirm:$False -Force | Out-Null
$viserverConnection = Connect-VIServer $vCenter

$MyCollection = @()	

$ClusterFilter = get-view -ViewType ClusterComputeResource -Property Name -Filter @{"Name" = $Cluster } | select -ExpandProperty MoRef
if ($VMparam.Length -lt 1 ) { $AllVMs = Get-View -ViewType VirtualMachine -SearchRoot $ClusterFilter | Where {-not $_.Config.Template} }
else { $AllVMs = Get-View -ViewType VirtualMachine -SearchRoot $ClusterFilter | Where {-not $_.Config.Template} | Where {$_.Name -imatch $VMparam} }

if ((get-cluster $cluster).vsanenabled -eq $true) { 

    if($ESXiHostUsername -eq "" -or $ESXiHostPassword -eq "") {
        Write-Host -ForegroundColor Red "You did not configure the ESXi host credentials, please update `$ESXiHostUsername & `$ESXiHostPassword variables and try again"
        return
    }

    $ClustervSANEnabled = $true 

    # Retrieve list of ESXi hosts from cluster
    # which we will need to directly connect to use call VsanQueryObjectIdentities()
    if ($VMparam) {
        $vmhosts = get-vm $VMparam -Server $viserverConnection | get-vmhost
    } else {
        $vmhosts = get-cluster $cluster | get-vmhost 
    }

    # Retrieve vSAN data 
    $vsanresults = @()
    foreach ($vmhost in $vmhosts) {
        $vmhostView = Get-vmhost $vmhost
        $esxiConnection = Connect-VIServer -Server $vmhostView.name -User $ESXiHostUsername -Password $ESXiHostPassword

        $vos = Get-VSANView -Id "VsanObjectSystem-vsan-object-system" -Server $esxiConnection
        $identities = $vos.VsanQueryObjectIdentities($null,$null,$null,$false,$true,$true)
        $json = $identities.RawData|ConvertFrom-Json
        $jsonResults = $json.identities.vmIdentities

        #one-time get vsan uuid's per vmhost
        $vsanIntSys = Get-View -Server $esxiConnection (Get-VMHost -Server $esxiConnection).ExtensionData.ConfigManager.vsanInternalSystem
      
        #loop through all vsan jost results per host
        foreach ($vmInstance in $jsonResults) {
            $identities = $vmInstance.objIdentities #| where type -Match "vdisk"
            foreach ($identity in $identities | Sort-Object -Property "type") {
                # Retrieve the VM Name
                if($identity.type -eq "namespace") {
                    $attributes = ($vsanIntSys.GetVsanObjExtAttrs($identity.uuid)) | ConvertFrom-JSON

                    foreach ($attribute in $attributes | Get-Member) {
                        # crappy way to iterate through keys ...
                        if($($attribute.Name) -ne "Equals" -and $($attribute.Name) -ne "GetHashCode" -and $($attribute.Name) -ne "GetType" -and $($attribute.Name) -ne "ToString") {
                            $objectID = $attribute.name
                            $vmName = $attributes.$($objectID).'User friendly name'
                        }
                    }
                }

                if (($VMparam) -and ($vmName -ne $VMparam)) {
                } else {  
                    # Convert B to MB
                    $physicalUsedMB = $identity.physicalUsedB/1MB
                    $RealUsedMB = $identity.primaryCapacityB/1MB
                    $SecuredOptimizedUsedMB = ((get-vm -Server $esxiConnection $vmName).ExtensionData.LayoutEx.File | ? {$_.name -eq $identity.description }).Size/1MB
                    $DedupCompressRatio = $physicalUsedMB / $SecuredOptimizedUsedMB
                    $vSANSLAFootPrint = $physicalUsedMB / $RealUsedMB
                }

                # Build our custom object to store only the data we care about
                    $tmp = [pscustomobject] @{
                        VM = $vmName
                        File = $identity.description;
                        Type = $identity.type;
                        physicalUsedMB = $physicalUsedMB;
                        RealUsedMB = $RealUsedMB;
                        SecuredOptimizedUsedMB = $SecuredOptimizedUsedMB;
                        DedupCompressRatio = $DedupCompressRatio;
                        vSANSLAFootPrint = $vSANSLAFootPrint;
                    }

                # Filter out a specific VM if provided
                if($VMparam) {
                    if($vmName -eq $VMparam) {
                        if ($tmp.Type -eq "vdisk") {
                            $vsanresults += $tmp
                        }
                    }
                } else {
                    if ($tmp.Type -eq "vdisk") {
                        $vsanresults += $tmp
                    }
                }
            }
        }
        Disconnect-VIServer -Server $esxiConnection -Confirm:$false
    }
    ###$vsanresults | Format-Table #gives per vmdk results filtered on vdisk type, maybe useful in the future
}


# rebuild vsanresults into array per VM and not per vmdk
[System.Collections.ArrayList]$vsanvmresults = @()
$tmp = [pscustomobject] @{
    VM = ""
    physicalUsedMB = ""
    RealUsedMB = ""
    SecuredOptimizedUsedMB = ""
    DedupCompressRatio = ""
    vSANSLAFootPrint = ""
}
$vsanvmresults += $tmp
foreach ($vsanresult in $vsanresults) {
    if ($vsanvmresults.VM.Contains($vsanresult.VM)) {
        $vmindex = $vsanvmresults.VM.IndexOf($vsanresult.VM)
        $vsanvmresults[$vmindex].physicalUsedMB += $vsanresult.physicalUsedMB
        $vsanvmresults[$vmindex].RealUsedMB += $vsanresult.RealUsedMB
        $vsanvmresults[$vmindex].SecuredOptimizedUsedMB += $vsanresult.SecuredOptimizedUsedMB
        $vsanvmresults[$vmindex].DedupCompressRatio = $vsanvmresults[$vmindex].physicalUsedMB/$vsanvmresults[$vmindex].SecuredOptimizedUsedMB
        $vsanvmresults[$vmindex].vSANSLAFootPrint = $vsanvmresults[$vmindex].physicalUsedMB/$vsanvmresults[$vmindex].RealUsedMB

    } else {
        $tmp = [pscustomobject] @{
            VM = $vsanresult.VM
            physicalUsedMB = $vsanresult.physicalUsedMB;
            RealUsedMB = $vsanresult.RealUsedMB;
            SecuredOptimizedUsedMB = $vsanresult.SecuredOptimizedUsedMB;
            DedupCompressRatio = $vsanresult.DedupCompressRatio;
            vSANSLAFootPrint = $vsanresult.vSANSLAFootPrint;
        }
        $vsanvmresults += $tmp
    }   
}
$vsanvmresults.RemoveAt(0)




$SortedVMs = $AllVMs | Select *, @{N="NumDisks";E={@($_.Guest.Disk.Length)}} | Sort-Object -Descending NumDisks	
ForEach ($VM in $SortedVMs){
    $VMmUNMAP = $false
    $VMaUNMAP = $false
    $DSmUNMAP = $false
    $DSaUNMAP = $false
    $EEaUNMAP = $false
    $VMtools = $false
    $Snapshot = "VM has snapshot(s), delete these first before UNMAP/Zero"
    $Details = New-object PSObject	
    $Details | Add-Member -Name Name -Value $VM.name -Membertype NoteProperty
    $getvm = get-vm $vm.name
    $DiskProvisionedVMDK = ($getvm | Select ProvisionedSpaceGB).ProvisionedSpaceGB	
    $DiskUsedSpaceVMDK = ($getvm | Select UsedSpaceGB).UsedSpaceGB
    $VMEsxiVersion = ($getvm | get-vmhost).version
    $toolsStatus = $VM.Guest.ToolsStatus
    if($toolsStatus -eq "toolsOk"){ $VMtools = $true }
    if($toolsStatus -eq "toolsOld"){ $VMtools = $true }
    
    #Check all thin disks
    if ( ($getvm | get-harddisk | where {$_.Storageformat -inotmatch "Thin"}).length -eq 0) { $DisksAllThin = $true }
    else { $DisksAllThin = $false }
    
    #Check CBT on disks
    $CBTEnabled = $VM.Config.ChangeTrackingEnabled
    
    #GuestOS
    $VMOS = ($getvm).ExtensionData.Guest.GuestFullName
    $VMOSFamily = ($getvm).ExtensionData.Guest.GuestFamily
    
    #Snapshots
    if (($getvm |Get-Snapshot).count -eq 0) { $Snapshot = "No Snapshots" }
    
    #VM Datastore Type
    $VMDS = $getvm | Get-Datastore | Select-Object -first 1
    $VMDSType = ($VMDS).Type
    if ($VMDSType -ne "vsan") { $VMDSVersion = ($getvm | Get-Datastore | Select-Object -first 1).FileSystemVersion.substring(0,1) }
    $DSType = $VMDSType + "" + $VMDSVersion
    $HWVersion = $vm.Config.Version -replace "vmx-",""
    
    if ($VMDSType -eq "NFS") {
        $DSmUNMAP = "NFS not supported"
        $DSaUNMAP = "NFS not supported"
    }

    if ($VMDSType -eq "vsan") {
        if ((Get-VsanClusterconfiguration -Cluster (get-cluster -VM $vm.name)| Select-Object guestTrimUnmap).guestTrimUnmap -eq $true) {
            $DSmUNMAP = $true
            $DSaUNMAP = $true
        }
    }
    
    #Check if ESXi / Datastore UNMAP enabled / possible
    #https://www.codyhosterman.com/2017/01/managing-in-guest-unmap-and-automatic-vmfs-6-unmap-with-powercli/
    #https://github.com/codyhosterman/powercli/blob/master/checkandfixUNMAP.ps1
    
    if ($VMDSType -eq "VMFS") {
        if ($esx.Version -like "6.*") {
            if ($VMDSVersion -ge 5) {
                $DSmUNMAP = $true
                $enableblockdelete = $esx | Get-AdvancedSetting -Name VMFS3.EnableBlockDelete
                if ($enableblockdelete.Value -eq 1) { $DSaUNMAP = $true }
            }
        }
        if ($esx.Version -like "6.5.*") {
            if ($VMDSVersion -ge 5) {
                $DSmUNMAP = $true
                $autounmap = $esx | Get-AdvancedSetting -Name VMFS3.EnableVMFS6Unmap
                if ($autounmap.Value -eq 1) { $DSaUNMAP = $true }
            }
            if ($VMDSVersion -eq 6) {
                $esx = ($getvm) | get-vmhost
                $esxcli=get-esxcli -VMHost $esx -v2
                $unmapargs = $esxcli.storage.vmfs.reclaim.config.get.createargs()
                $unmapargs.volumelabel = $vmds.name
                $unmapresult = $esxcli.storage.vmfs.reclaim.config.get.invoke($unmapargs).ReclaimPriority
                if ($unmapresult -eq "None") {
                    $DSaUNMAP = $false
                } else {
                    $DSaUNMAP = $true
                }
            }
        }
    }
    
    #Check if Guest support manual and/or auto unmap
    if ($DisksAllThin -eq $true) {
        if ($HWVersion -ge 11) {
            if ($VMOS -imatch "Windows") {
                if (($VMOS -imatch "Windows Server 2003") -or ($VMOS -imatch "Windows Server 2008") -or ($VMOS -imatch "Windows XP") -or ($VMOS -imatch "Windows 7")) { $VMmUNMAP = $true }
                if (($VMOS -imatch "Windows Server 2012") -or ($VMOS -imatch "Windows Server 2016") -or ($VMOS -imatch "Windows Server 2019") -or ($VMOS -imatch "Windows 8") -or ($VMOS -imatch "Windows 10")) { 
                    $VMmUNMAP = $true 
                    #Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\FileSystem" -Name DisableDeleteNotification
                    $objReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $vm.name)
                    $objRegKey=$objReg.OpenSubKey("System\\CurrentControlSet\\Control\\FileSystem")
                    $VMDisableDeleteNotify = $objRegkey.GetValue("DisableDeleteNotification")
                    if ($VMDisableDeleteNotify -eq 0) {
                        $VMaUNMAP = $true 
                    }
                }
            }
            if ($VMOSFamily -ieq "linuxGuest") {
                if ($esx.Version -like "6.5.*") {
                    $VMmUNMAP = $true
                    $VMaUNMAP = "True, but only when mounted with the discard option"
                }
            }
        }
    }
    
    $DiskNum = 0
    $DiskCapacityVM = 0
    $DiskFreeSpaceVM = 0
    Foreach ($disk in $VM.Guest.Disk){
        $DiskCapacityVM += $disk.Capacity
        $DiskFreeSpaceVM += $disk.FreeSpace
        $DiskNum++
    }

    if ($ClustervSANEnabled -eq $true) {
        $vmindex = $vsanvmresults.VM.IndexOf($VM.name)
        $DiskUsedSpaceVMDK = ([math]::Round($vsanvmresults[$vmindex].RealUsedMB))
    } else {
        $DiskUsedSpaceVMDK = ([math]::Round($DiskUsedSpaceVMDK * 1024))
    }
    $DiskProvisionedVMDK = ([math]::Round($DiskProvisionedVMDK * 1024))
    $DiskCapacityVM = ([math]::Round($DiskCapacityVM/ 1MB))
    $DiskFreeSpaceVM = ([math]::Round($DiskFreeSpaceVM/ 1MB))
    $DiskUsedSpaceVM = $DiskCapacityVM - $DiskFreeSpaceVM
    #if($VMtools -eq $true) {
    #    $DiskPotentialFreeSpace = $DiskUsedSpaceVMDK - ($DiskCapacityVM - $DiskFreeSpaceVM)
    #} else {
    #    $DiskPotentialFreeSpace = ([math]::Round(0/ 1MB))
    #}
    if ($DiskCapacityVM -gt 0) {
        $DiskPotentialFreeSpace = $DiskUsedSpaceVMDK - ($DiskCapacityVM - $DiskFreeSpaceVM)
    } else {
        $DiskPotentialFreeSpace = ([math]::Round(0/ 1MB))
    }
    
    if (($VMaUNMAP -eq $true) -and ($DSaUNMAP -eq $true)) { $EEaUNMAP = $true }
    if (($VMaUNMAP -eq $true) -and ($VMDSType -eq "NFS")) { $EEaUNMAP = $false }
    #if ($VMmUNMAP -eq $true) { $VMmUNMAP = "If misaligned, you may need ESXi 6.5 Patch 1, ESXi650-201703001, build 5146846" }
    
    $Details | Add-Member -Name "End-to-End Auto UNMAP" -Value $EEaUNMAP -Membertype NoteProperty	
    $Details | Add-Member -Name "PotentialFreeSpace" -Value $DiskPotentialFreeSpace -Membertype NoteProperty
    $Details | Add-Member -Name "ProvisionedVMDK" -Value $DiskProvisionedVMDK -Membertype NoteProperty	
    $Details | Add-Member -Name "UsedSpaceVMDK" -Value $DiskUsedSpaceVMDK -Membertype NoteProperty	
    $Details | Add-Member -Name "CapacityVM" -Value $DiskCapacityVM -Membertype NoteProperty	
    $Details | Add-Member -Name "FreeSpaceVM" -Value $DiskFreeSpaceVM -Membertype NoteProperty	
    $Details | Add-Member -Name "UsedSpaceVM" -Value $DiskUsedSpaceVM -Membertype NoteProperty	
    $Details | Add-Member -Name "VM ManualUNMAP" -Value $VMmUNMAP -Membertype NoteProperty	
    $Details | Add-Member -Name "VM AutoUNMAP" -Value $VMaUNMAP -Membertype NoteProperty
    $Details | Add-Member -Name "Storage ManualUNMAP" -Value $DSmUNMAP -Membertype NoteProperty	
    $Details | Add-Member -Name "Storage AutoUNMAP" -Value $DSaUNMAP -Membertype NoteProperty
    $Details | Add-Member -Name "DisksAllThin" -Value $DisksAllThin -Membertype NoteProperty	
    $Details | Add-Member -Name "CBTEnabled" -Value $CBTEnabled -Membertype NoteProperty
    $Details | Add-Member -Name "ESXiVersion" -Value $VMEsxiVersion -Membertype NoteProperty
    $Details | Add-Member -Name "Datastore Type" -Value $DSType -Membertype NoteProperty
    $Details | Add-Member -Name "OS" -Value $VMOS -Membertype NoteProperty
    $Details | Add-Member -Name "HWVersion" -Value $HWVersion -Membertype NoteProperty
    $Details | Add-Member -Name "Snapshots" -Value $Snapshot -Membertype NoteProperty
    if ($ClustervSANEnabled -eq $true) {
        $vmindex = $vsanvmresults.VM.IndexOf($VM.name)
        $Details | Add-Member -Name "vSAN physicalUsedMB" -Value $vsanvmresults[$vmindex].physicalUsedMB -Membertype NoteProperty
        $Details | Add-Member -Name "vSAN RealUsedMB" -Value $vsanvmresults[$vmindex].RealUsedMB -Membertype NoteProperty
        $Details | Add-Member -Name "vSAN SecuredOptimizedUsedMB" -Value $vsanvmresults[$vmindex].SecuredOptimizedUsedMB -Membertype NoteProperty
        $Details | Add-Member -Name "vSAN DedupCompressRatio" -Value $vsanvmresults[$vmindex].DedupCompressRatio -Membertype NoteProperty
        $Details | Add-Member -Name "vSAN SLAFootPrint" -Value $vsanvmresults[$vmindex].vSANSLAFootPrint -Membertype NoteProperty
    }
    $MyCollection += $Details
}
$Details = New-object PSObject	
$TotalPotentialFreeSpace = ($MyCollection | Measure-Object 'PotentialFreeSpace' -Sum).Sum
$Details | Add-Member -Name Name -Value "TOTAL Potential Freespace" -Membertype NoteProperty
$Details | Add-Member -Name "PotentialFreeSpace" -Value $TotalPotentialFreeSpace -Membertype NoteProperty
$MyCollection += $Details

if ($ExportCSV.Length -lt 1 ) { 
    $MyCollection | Out-GridView -Title "vSphere Freespace and UNMAP Identifier $version"
} else {
    $MyCollection | Export-Csv -Path $ExportCSV -Encoding UTF8 -NoTypeInformation -UseCulture
}

