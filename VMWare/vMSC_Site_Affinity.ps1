<#  
    .SYNOPSIS
    Sets VM-to-Host soft affinity (should not must) in a vMSC scenario where site affinity is preferred.
    vMSC Site Affinity
    .DESCRIPTION
    Scripts sets fills DRS Host groups and DRS VM groups for all existing cluster in a stretched datacenter
    and creates DRS Rules with soft VM-to-Host affinity based on the VM's used datastores.
    The scripts needs to know the ESXi Hosts per site and datastores per site; see the VARS section below.
    It also mails you a report if needed every runtime and tells you which VM's use datastores from both sites.
    Only works with two sites!
    v0.4 added/fixed:
    - support for wildcards in datastore and host variables, like odd/even.
    - support for datastore wildcard exclusion (needed for commvault netapp integration)
    - support for defining clusters (instead of all)
    - extra output in log and mail of VM's running cross, for example a VM with storage on site A en running on a host in site B.
    - fix for environments with multiple VMHostAffinity rules (outside this script)
    .NOTES
    By Jan Jaap van Santen
    github: janjaaps
    email: github@lebber.net
    email: janjaap@scict.nl
    vMSC Info
    Good read: http://www.vmware.com/files/pdf/techpaper/vmware-vsphere-metro-storage-cluster-recommended-practices.pdf
    By Duncan Epping
    .LINK
    https://github.com/janjaaps/powershell
    http://scict.nl/
    .EXAMPLE
    Just fill the VARS and run, PowerCLI needed
    Run by using task schedular "powershell -file "vMSC Site Affinity.ps1" "
#>
 
### VARS DONT TOUCH
$version = "v0.4"
### VARS
$reportemailserver = 'mailserver.local' 
$reportemailsubject = 'vMSC Site Affinity'
$reportemailadresfrom = 'vMSC@local'
$reportemailadresto = 'jsanten@local'
$vcenterserver = 'vcenter.local' # (single vcenter)
$SiteA_name = '_MER A' # Site A prefix for DRS groups & rules
$SiteB_name = '_MER B' # Site A prefix for DRS groups & rules
$siteA_datastores = 'nfsvm_01a_ds01_tier1','nfsvm_01b_ds02_tier1' # comma separated datastores, datastore clusters, or use wildcards *[0-9][13579]*, e.g. datastores with odd numbers between 00-99
$siteB_datastores = 'nfsvm_02a_ds03_tier1','nfsvm_02b_ds11_tier2' # comma separated datastores, datastore clusters, or use wildcards *[0-9][02468]*, e.g. datastores with even numbers between 00-99
$siteX_datastores_exclude = "BACKUP" # wildcard for exclusion in datastores, feature needed for commvault
$siteA_hosts = 'esx01.local','esx03.local','esx05.local','esx07.local','ora41.local' # comma separated esxi hosts, or use wildcards *[0-9][13579]* e.g. hosts with odd numbers between 00-99
$siteB_hosts = 'esx02.local','esx04.local','esx06.local','esx08.local','ora42.local' # comma separated esxi hosts, or use wildcards *[0-9][02468]* e.g. hosts with even numbers between 00-99
$siteX_clusters = '*' # comma separated esxi hosts, or use wildcards *PROD[0-9]*
$doReport = $True # Option to report/mail
$logfile = "c:\test.log"
$RunDRS = "1" # 0 for no, 1 for yes to run DRS immediately afterwards
Clear-Content $logfile
 
function Update-DrsVMGroup {
<#
.SYNOPSIS
Update DRS VM group with a new collection of VM´s
 
.DESCRIPTION
Use this function to update the ClusterVMgroup with VMs that are sent in by parameters
 
.PARAMETER  xyz 
 
.NOTES
Author: Niklas Akerlund / RTS (most of the code came from http://communities.vmware.com/message/1667279 @LucD22 and GotMoo)
Date: 2012-06-28
#>
    param (
    $cluster,
    $VMs,
    $groupVMName)
    
    $cluster = Get-Cluster $cluster
    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
    $groupVM = New-Object VMware.Vim.ClusterGroupSpec
    #Operation edit will replace the contents of the GroupVMName with the new contents seleced below.
    $groupVM.operation = "edit" 
 
    $groupVM.Info = New-Object VMware.Vim.ClusterVmGroup
    $groupVM.Info.Name = $groupVMName 
 
    Get-VM $VMs | %{
        $groupVM.Info.VM += $_.Extensiondata.MoRef
    }
    $spec.GroupSpec += $groupVM
 
    #Apply the settings to the cluster
    $cluster.ExtensionData.ReconfigureComputeResource($spec,$true)
}
 
##### MAILER
Function Mailer
{
$message = New-Object System.Net.Mail.MailMessage $reportemailadresfrom, $reportemailadresto
$message.Subject = $reportemailsubject
$message.Body = ""
$message.Attachments.Add($logfile)
 
$smtp = New-Object Net.Mail.SmtpClient($reportemailserver)
$smtp.Send($message)
} 
 
##### WriteLogScreen
function WriteLogScreen {
   Param ([string]$logstring)
   $logstring | out-file -Filepath $logfile -append
   write-host "$logstring"
}
 
# using VMware.VimAutomation.Core
cls
if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null )
{
    Add-PsSnapin VMware.VimAutomation.Core
}
if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null )
 
{ Write-host "--------------------------------------`nNo PowerCLI Snap-In found.`nPlease install VMWare PowerCLI first`n--------------------------------------"
Write-Host "Press any key to exit and launch a browser to the VMware PowerCLI page."
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Start-Process -FilePath "https://developercenter.vmware.com/tool/vsphere_powercli/6.0"
}
else {
WriteLogScreen "------------------------------------------------------------------------------------------"
WriteLogScreen "           __  __ ____   ____   ____  _ _            _     __  __ _       _ _         "
WriteLogScreen "    __   _|  \/  / ___| / ___| / ___|(_) |_ ___     / \   / _|/ _(_)_ __ (_) |_ _   _ "
WriteLogScreen "    \ \ / / |\/| \___ \| |     \___ \| | __/ _ \   / _ \ | |_| |_| | '_ \| | __| | | |"
WriteLogScreen "     \ V /| |  | |___) | |___   ___) | | ||  __/  / ___ \|  _|  _| | | | | | |_| |_| |"
WriteLogScreen "      \_/ |_|  |_|____/ \____| |____/|_|\__\___| /_/   \_\_| |_| |_|_| |_|_|\__|\__, |"
WriteLogScreen "                                                                                |___/ $version"
WriteLogScreen "------------------------------------------------------------------------------------------"
}
 
### Fix possible invalid cert
Set-PowerCLIConfiguration -InvalidCertificateAction warn -scope session -Confirm:$False
 
#Connecting vCenter
write-host "`nConnecting to VMware server", $vcenterserver,"(waiting for logon window)...`n"
Connect-VIServer $vcenterserver;
#User will be prompted for login automatically
 
#Find VMs in site (by datastore)
$vmsA = @(); # array of strings for VM names in datastores site A
$vmsB = @(); # array of strings for VM names in datastores site B
$vmsA = get-vm -Datastore $siteA_datastores | Where-Object {$_.Name -inotmatch $siteX_datastores_exclude}
$vmsB = get-vm -Datastore $siteB_datastores | Where-Object {$_.Name -inotmatch $siteX_datastores_exclude}
 
#Find VMs currently running on the wrong site.
#Storage on Site A, VM running Site B
#$vmsAB = get-vm -Datastore $siteA_datastores | Where-Object {$siteB_hosts -contains $_.VMHost.Name}
#$vmsAB = get-vm -Datastore $siteA_datastores | Where-Object {$_.VMHost.Name -like $siteB_hosts}
$vmsAB = get-vm -Datastore $siteA_datastores | Where-Object {$_.Name -inotmatch $siteX_datastores_exclude} | Where-Object {$_.VMHost.Name -like $siteB_hosts -or $siteB_hosts -contains $_.VMHost.Name} | sort
#Storage on Site B, VM running Site A
#$vmsBA = get-vm -Datastore $siteB_datastores | Where-Object {$siteA_hosts -contains $_.VMHost.Name}
#$vmsBA = get-vm -Datastore $siteB_datastores | Where-Object {$_.VMHost.Name -like $siteA_hosts}
$vmsBA = get-vm -Datastore $siteB_datastores | Where-Object {$_.Name -inotmatch $siteX_datastores_exclude} | Where-Object {$_.VMHost.Name -like $siteA_hosts -or $siteA_hosts -contains $_.VMHost.Name} | sort
 
#Find VMs in both arrays (double site VMs)
$vmsC = @(); # array of strings for VM names in datastores from both site A and B$vms
$vmsC = Compare-Object $vmsA $vmsB -IncludeEqual -ExcludeDifferent -PassThru
 
#Clear site A + B arrays with double site VMs
if ($vmsC -ne $null) {
$vmsA = Compare-Object $vmsA $vmsC -PassThru
$vmsB = Compare-Object $vmsB $vmsC -PassThru
}
 
#Find VMs in both arrays (double site VMs)
$hostsA = @(); # array of strings for ESXi host names
$hostsA = get-vmhost $siteA_hosts
$hostsB = @(); # array of strings for ESXi host names
$hostsB = get-vmhost $siteB_hosts
 
$vmsACount = $vmsA.Count
$vmsBCount = $vmsB.Count
$vmsABCount = $vmsAB.Count
$vmsBACount = $vmsBA.Count
$vmsCCount = $vmsC.Count
$datacenter = Get-Datacenter
 
WriteLogSCreen "$(Get-Date -format s)"
WriteLogScreen "------------------------------------------------------------------------------------------"
WriteLogScreen "vCenter Server                      : $vcenterserver"
WriteLogScreen "Datacenter                          : $datacenter"
WriteLogScreen "VM's Site A                         : $vmsACount"
WriteLogScreen "VM's Site B                         : $vmsBCount"
WriteLogScreen "VM's Storage Site A, Running Site B : $vmsABCount"
WriteLogScreen "VM's Storage Site B, Running Site A : $vmsBACount"
WriteLogScreen "VM's Double Site Storage            : $vmsCCount"
 
#Run trhough each cluster
$clusters = @(); # array of clusters
$clusters = Get-Cluster $siteX_clusters | sort
foreach ($c in $clusters) {
    $clusterhosts = @();
    $clusterhosts = Get-VMHost -Location $c
    $clustervms = @();
    $clustervms = Get-VM -Location $c
    $clusterhosts_siteA = Compare-Object $clusterhosts $hostsA -IncludeEqual -ExcludeDifferent -PassThru | sort
    $clusterhosts_siteB = Compare-Object $clusterhosts $hostsB -IncludeEqual -ExcludeDifferent -PassThru | sort
    $clustervms_siteA = Compare-Object $clustervms $vmsA -IncludeEqual -ExcludeDifferent -PassThru | sort
    $clustervms_siteB = Compare-Object $clustervms $vmsB -IncludeEqual -ExcludeDifferent -PassThru | sort
    WriteLogScreen "------------------------------------------------------------------------------------------"
    WriteLogScreen "Cluster: $c"
    WriteLogScreen "------------------------------------------------------------------------------------------"
    #write-host "Hosts Site A:" $clusterhosts_siteA
    #write-host "Hosts Site B:" $clusterhosts_siteB
    #write-host "VMs Site A:" $clustervms_siteA
    #write-host "VMs Site B:" $clustervms_siteB
    #write-host "------------------------------------------------------------------------------------------"
 
    ### DRSRule Site A, first Check if Drs-Rule exists site A
    $drsrule_siteA = @();
    $drsrule_siteA = get-drsrule -Cluster $c.Name -type VMHostAffinity
    if ($drsrule_siteA.name -contains $SiteA_name) {
        WriteLogScreen "$SiteA_name : Updating DRS VM Group VM$SiteA_name"
        WriteLogScreen "$SiteA_name : Updating DRS VM Group with VMs:"
        foreach ($i in $clustervms_siteA) { WriteLogScreen "- $i" }
        Update-DrsVMGroup -cluster $c -VMs $clustervms_siteA -groupVMName VM$SiteA_name
    } else {
        WriteLogScreen "$SiteA_name : Creating DRS VM/Host Rule with Hosts:"
        foreach ($i in $clusterhosts_siteA) { WriteLogScreen "- $i" }
        WriteLogScreen "$SiteA_name : Creating DRS VM/Host Rule with VMs:"
        foreach ($i in $clustervms_siteA) { WriteLogScreen "- $i" }
        New-DRSGroupRule -cluster $c -VMs $clustervms_siteA -VMHosts $clusterhosts_siteA -Name $SiteA_name
    }
    WriteLogScreen "---" 
    ### DRSRule Site B, first Check if Drs-Rule exists site B
    $drsrule_siteB = @();
    $drsrule_siteB = get-drsrule -Cluster $c.Name -type VMHostAffinity
    if ($drsrule_siteB.name -contains $SiteB_name) {
        WriteLogScreen "$SiteB_name : Updating DRS VM Group VM$SiteB_name"
        WriteLogScreen "$SiteB_name : Updating DRS VM Group with VMs:" 
        foreach ($i in $clustervms_siteB) { WriteLogScreen "- $i" }
        Update-DrsVMGroup -cluster $c -VMs $clustervms_siteB -groupVMName VM$SiteB_name
    } else {
        WriteLogScreen "$SiteB_name : Creating DRS VM/Host Rule with Hosts:"
        foreach ($i in $clusterhosts_siteB) { WriteLogScreen "- $i" }
        WriteLogScreen "$SiteB_name : Creating DRS VM/Host Rule with VMs:" 
        foreach ($i in $clustervms_siteB) { WriteLogScreen "- $i" }
        New-DRSGroupRule -cluster $c -VMs $clustervms_siteB -VMHosts $clusterhosts_siteB -Name $SiteB_name
    }
 
 
}
 
WriteLogScreen "------------------------------------------------------------------------------------------"
WriteLogScreen "VM's Storage Site A, Running Site B"
WriteLogScreen "------------------------------------------------------------------------------------------"
foreach ($i in $vmsAB) { WriteLogScreen "- $i" }
 
WriteLogScreen "------------------------------------------------------------------------------------------"
WriteLogScreen "VM's Storage Site B, Running Site A"
WriteLogScreen "------------------------------------------------------------------------------------------"
foreach ($i in $vmsBA) { WriteLogScreen "- $i" }
 
WriteLogScreen "------------------------------------------------------------------------------------------"
WriteLogScreen "VM's Double Site Storage"
WriteLogScreen "------------------------------------------------------------------------------------------"
foreach ($i in $vmsC) { WriteLogScreen "- $i" }
 
 
###http://vniklas.djungeln.se/2012/06/28/vsphere-cluster-host-vm-rule-affinity-with-powercli/
function New-DRSGroupRule{
<#
.SYNOPSIS
Create a new DRSGroupRule for VMs to reside on some hosts in a cluster
 
.DESCRIPTION
Use this function to create vms in a group and hosts in a group and a host-vm affinity
 
.PARAMETER  MustRun
A switch that will create the rule with Must Run on these host, if not set it will create the rule with should run.
 
.NOTES
Author: Niklas Akerlund / RTS (most of the code came from http://communities.vmware.com/message/1667279 @LucD22 and GotMoo)
Date: 2012-06-28
#>
    param (
    [Parameter(Position=0,Mandatory=$true,HelpMessage="A Cluster",
    ValueFromPipeline=$True)]
    $cluster,
    $VMHosts,
    $VMs,
    [string]$Name,
    [switch]$MustRun
    )
    
    $cluster = Get-Cluster $cluster
 
    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
    $groupVM = New-Object VMware.Vim.ClusterGroupSpec
    $groupVM.operation = "add" 
    $groupVM.Info = New-Object VMware.Vim.ClusterVmGroup
    $groupVM.Info.Name = "VM$Name"
 
    Get-VM $VMs | %{
   $groupVM.Info.VM += $_.Extensiondata.MoRef
    }
    $spec.GroupSpec += $groupVM
 
    $groupESX = New-Object VMware.Vim.ClusterGroupSpec
    $groupESX.operation = "add"
    $groupESX.Info = New-Object VMware.Vim.ClusterHostGroup
    $groupESX.Info.Name = "Host$Name"
 
    Get-VMHost $VMHosts | %{
    $groupESX.Info.Host += $_.Extensiondata.MoRef
    }
    $spec.GroupSpec += $groupESX
 
    $rule = New-Object VMware.Vim.ClusterRuleSpec
    $rule.operation = "add"
    $rule.info = New-Object VMware.Vim.ClusterVmHostRuleInfo
    $rule.info.enabled = $true
    $rule.info.name = $Name
    if($MustRun){
        $rule.info.mandatory = $true
    }else{
        $rule.info.mandatory = $false
    }
    $rule.info.vmGroupName = "VM$Name"
    $rule.info.affineHostGroupName = "Host$Name"
    $spec.RulesSpec += $rule
 
    $cluster.ExtensionData.ReconfigureComputeResource($spec,$true)
}
 
 
 
if ($RunDRS) { 
WriteLogScreen "------------------------------------------------------------------------------------------"
WriteLogScreen "Running DRS Recommendations"
Get-DrsRecommendation -Refresh| Invoke-DrsRecommendation
WriteLogScreen "------------------------------------------------------------------------------------------"
}
 
if ($doreport) { mailer } 
 
 
Disconnect-VIServer $vcenterserver -Confirm:$False;