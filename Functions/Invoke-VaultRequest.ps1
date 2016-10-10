Set-StrictMode -Version Latest
function Ignore-SelfSignedCerts {
    #This code disables SSL Checking
    add-type -TypeDefinition  @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

function Invoke-VaultRequest {
    [cmdletbinding()]
    param (
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $VaultPath=$(throw "VaultPath is mandatory, please provide a value"),

        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $HttpMethod=$(throw "HttpMethod is mandatory, please provide a value"),

        [parameter(mandatory=$false)]
        [object]
        $HttpHeaders,

        [parameter(mandatory=$false)]
        [boolean]
        $IgnoreSSL,

        [parameter(mandatory=$false)]
        [object]
        $HttpBody
    )

    process {
        $listOfServers = $env:Vault_Servers.split(";")
        $currentCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy
        
        if ($HttpBody){
            $HttpBody = $HttpBody  | ConvertTo-Json
        }

        if($IgnoreSSL){
            try{
                Ignore-SelfSignedCerts
            } catch {
                Write-Warning "looks like there was an issue trying to ignore SSL: $_"
            }
        }
        
        #By Default Powershell uses Tls1. Need to set it to use Tls12 to logon to Vault
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try{
            #If VaultPath doesn't start with /; add it to the path
            if(!($VaultPath.StartsWith('/') ) ){
                $VaultPath = "/" + $VaultPath
            }

            $i = 0
            $healthyVaultRequest = $false
            $result = $null
            while( $i -lt $listOfServers.Count -and $result -eq $null ){
                if($listOfServers[$i]){
                    try{
                        $uri = 'https://' + $listOfServers[$i] + "$VaultPath"
                        write-debug "Server is: $uri"
                    
                        $parameters = @{
                            Method = $HttpMethod;
                            Headers = $HttpHeaders;
                            Uri = $uri;
                            Body = $HttpBody;
                            UseBasicParsing = $true;
                            MaximumRedirection = 2
                        }
                        
                        $result = Invoke-WebRequest @parameters
                        
                        if ($result -eq $null){
                            throw "HTTP Request to ${uri} returned null"
                        }
                    } catch {
                        write-warning "error calling ${uri}"
                        write-warning $_
                        $errorMessage = $_
                    }
                }
                $i++
            }
        }
        catch {
            [System.Net.ServicePointManager]::CertificatePolicy = $currentCertPolicy
            throw $_
        }
        #Reset Certificate Policy
        [System.Net.ServicePointManager]::CertificatePolicy = $currentCertPolicy
        
        if($result){
            return $result
        } else {
            if ($errorMessage){
                throw "Invoke-VaultRequest is unable to get a healthy response: $errorMessage"
            }
            else{
                throw "Invoke-VaultRequest errored out"
            }
        }
    }
}