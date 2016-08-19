Set-StrictMode -Version Latest

function Get-VaultSecret {
<#
.SYNOPSIS
Used to the a secret from vault. Requires Set-VaultDefaults / Get-VaultToken to be executed prior to running this function.
Returns a hashtable of results from Vault

.DESCRIPTION
Will return a hashtable of results from Vault

.PARAMETER VaultPath
The path of the vault secret. eg: v1/exampleRole/msqlpassword

.PARAMETER VaultToken
The System.Security.SecureString object of the vault token.

.PARAMETER IgnoreSSL
A boolean value to ignore SSL errors or not

.EXAMPLE
Set-VaultDefaults -Servers ['vaultexamplea.com', 'vaultexampleb.com']
$vaultToken = Get-VaultToken
$results = Get-VaultSecret -VaultPath 'v1/exampleRole/mssqlpassword' -VaultToken $vaultToken
#>
    [cmdletbinding()]
    param (
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $VaultPath=$(throw "VaultPath is mandatory, please provide a value"),

        [parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $VaultToken=$(throw "VaultToken is mandatory, please provide a secure string"),

        [parameter(mandatory=$false)]
        [boolean]
        $IgnoreSSL = $false
    )
    
    process {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($VaultToken)
        $tokenPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        $header = @{
            'X-Vault-Token' = $tokenPlainText;
        }
        
        $parameters = @{
            VaultPath = $VaultPath;
            HttpMethod = 'Get';
            IgnoreSsl = $IgnoreSSL;
            HttpHeaders = $header
        }
        
        try{
            $result = Invoke-VaultRequest @parameters
            
            if ($result.StatusCode -ne 200) {                
                write-error 'HTTP Status code was not 200'
                $statusCode = $result.StatusCode                
                throw "HTTP Status Code was not 200. It was: ${StatusCode}"
            }
            try{
                $resultContent = $result.Content | ConvertFrom-Json
                return $resultContent.data
            }catch{
                throw "unable to return a set of results - cannot convert from json: $_"
            }
        } catch {
            $ErrorMessage = $_.Exception.Message            
            throw "Could not get Vault Secret: ${ErrorMessage}"
        }
    }
}
