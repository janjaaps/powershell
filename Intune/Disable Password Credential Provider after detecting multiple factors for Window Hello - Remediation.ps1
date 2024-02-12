$registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$registryValueName = "ExcludedCredentialProviders"
$registryValueData = "{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" #Password Credential Provider

try {
    if(!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force
        New-ItemProperty -Path $registryPath -Name $registryValueName -Value $registryValueData -PropertyType String -Force
        Write-Host "Successfully configured Windows Hello for Business as required" 
    }
    else {
        New-ItemProperty -Path $registryPath -Name $registryValueName -Value $registryValueData -PropertyType String -Force
        Write-Host "Successfully configured Windows Hello for Business as required" 
    }
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Error $errorMessage
    exit 1 
}
