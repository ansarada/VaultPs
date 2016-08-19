Set-StrictMode -Version Latest

function Get-VaultToken {

<#
.SYNOPSIS
Used to authenticate into vault. Requires Set-VaultDefaults to be executed prior to running this function.
Returns a secure string for the Vault Token

.DESCRIPTION
This will return a secure string for the Vault token.

.EXAMPLE
Set-VaultDefaults -Servers ['vaultexamplea.com', 'vaultexampleb.com']
$authToken = Get-VaultToken
#>
    [cmdletbinding()]
    Param()

    process {
        write-debug "Get Policy Document"
        $instancePkcs7Document = $null
        $i = 0
        while ( ($instancePkcs7Document -eq $null) -and ($i -lt 3) ) {            
            $i++
            try{
                $instancePkcs7Document = (Invoke-WebRequest -Uri 'http://169.254.169.254/latest/dynamic/instance-identity/pkcs7').Content                
            }
            catch{
                sleep 2                
                write-warning "Could not get instance policy document"
            }
        }
        if ($instancePkcs7Document -eq $null){
            throw "Could not get instance policy document"
        }        
        
        $body = @{
            pkcs7 = "$instancePkcs7Document";
            role = $env:Vault_Role;
            nonce = $env:Vault_Nonce
        }

        $parameters = @{
            VaultPath = 'v1/auth/aws-ec2/login';
            HttpMethod = 'Post';
            IgnoreSsl = $true;
            HttpBody = $body
        }
        
        try{
            
            $result = Invoke-VaultRequest @parameters            
            write-debug "successfully retrieved token"
            if ($result){
                $resultContent = $result.Content | ConvertFrom-Json
                $secureToken = $resultContent.auth.client_token | ConvertTo-SecureString -AsPlainText -Force
                $resultContent = $null
                $result = $null
                
                return $secureToken
            } else {
                throw "No result returned"
            }
        } catch {
            $ErrorMessage = $_.Exception.Message
            throw "Could not get Vault Auth token: $ErrorMessage"
        }
    }
}
