<#  
    .SYNOPSIS
    Creates a GFS like retention schema with the normal backup to tape job type
    Only use this for tape in a normal media pool!
    All used/non-free and online tapes are protected!
    .DESCRIPTION
    The Script sets tape protection for MONTH and YEAR retention, scheduling takes place in windows schedular
    and should run on the day the tape copies start (weekend), this to calculate the correct week nummer.
    The script sleeps until monday morning so tapes are protected after backup but before the tapes are changed.
    We run this at 23:59 PM on the first friday of each month, the script sleeps until monday morning 06:00 AM.
    Set weekend of MONTH do MONTHLY with set retention (protect it and take it out after set retention)
    Set weekend of YEAR  do YEARLY  with set retention (protect it and take it out after set retention)
    Should be easy to add quarterlies...
    Off course the script could be way more elegant; checking the jobs started at date X and check the tapes which were used.
    Fine if you've got the time, this was way quicker to implement and fits our needs :)
    .NOTES
    By Jan Jaap van Santen
    github: janjaaps
    email: github@lebber.net
    email: janjaap@scict.nl
    .LINK
    https://github.com/janjaaps/powershell
    http://scict.nl/
    .EXAMPLE
    Set the VARS according to your needs
    Run by using task schedular "powershell -file "vMSC Site Affinity.ps1" "
#>


# Load Veeam Snap-In
Add-PsSnapin -Name VeeamPSSnapIn -ErrorAction SilentlyContinue
clear


$SLEEPTIME = 175020 # 60 + (3600*24 ) + (3600*24) + (360*6) = 175020
$MEDIAPOOL = "Media Pool"
$MONTH = 2,3,4,5,6,7,8,9,10,11,12 # month id comma seperated
$MONTHRETENTION = 365.25 # in days
$YEAR = 1 # month id comma seperated
$YEARRETENTION = 1826.25 # in days
$DESCRIPTIONDATE = get-date -format "yyyy-MM"

##### Sleep for the weekend
#start-sleep -s $SLEEPTIME

##### Protect the tapes
$Tapes = Get-VBRTapeMedium | ?{$_.Location -notmatch "None" -and $_.MediaSet -like $MEDIAPOOL -and $_.IsFree -eq $false -and $_.ProtectedBySoftware -eq $false}  
foreach ($Tape in $Tapes) { 
    Set-VBRTapeMedium -Medium $Tape.Barcode -Description $descriptiondate
    Enable-VBRTapeProtection -medium $Tape.Barcode
    Write-output "Protected tape $Tape with Description: $descriptiondate"
}


##### Get tapes out of protection
$Tapes = Get-VBRTapeMedium | ?{$_.MediaSet -like $MEDIAPOOL -and $_.ProtectedBySoftware -eq $true}  
foreach ($Tape in $Tapes) { 

    $Retire=$false
    $tapeyear=[int] $tape.description.substring(0,4)
    $tapemonth=[int] $tape.description.substring(5,2)
    $date1=get-date -date "01/$tapemonth/$tapeyear"
    $date2=get-date
    $timediff = (New-TimeSpan -start $date1 -end $date2).TotalDays
    $MONTH.contains($tapemonth)
    if (($MONTH.contains($tapemonth)) -and ($timediff -ge $MONTHRETENTION)) { $retire = $true }
    if (($YEAR -eq $tapemonth) -and ($timediff -ge $YEARRETENTION)) { $retire = $true }
    if ($retire) {
        Set-VBRTapeMedium -Medium $Tape.Barcode -Description ""
        Disable-VBRTapeProtection -medium $Tape.Barcode
        write-output "Checking retirement for $tape Year: $tapeyear, Month: $tapemonth : Retired."
    }
    else {
        write-output "Checking retirement for $tape Year: $tapeyear, Month: $tapemonth : No retirement needed."
    }
}