
function Get-AADTokenWithCert
{
    [CmdletBinding()]
    param(
    [Parameter(Mandatory = $true)]
    $ClientID,
    [Parameter(Mandatory = $true)]
    $TenantId,
    [Parameter(Mandatory = $true)]
    $RedirectUri,
    [Parameter(Mandatory = $true)]
    $CertificateThumbprint,
    [Parameter(Mandatory = $false)]
    $Resource = "https://graph.microsoft.com")


    $OAuthCert = Get-ChildItem -Path "cert:\" -Recurse | Where-Object {$_.Thumbprint -match $CertificateThumbprint -and $_.HasPrivateKey -eq $true} | Select-Object -First 1
    If($OAuthCert -eq $null)
    {
        Write-Error "Unable OAuth Certificate in Local Stores"
        exit
    }
    #Create Confidential Client App
    $ConfidentialClient = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($clientid)
    #Configure Client with Auth Certificate
    [void]$ConfidentialClient.WithCertificate($OAuthCert)
    #Configure Client with Tenant Specific Authority
    [void]$ConfidentialClient.WithAuthority(("https://login.microsoftonline.com/" + $TenantID))
    #Define default scope
    $scopes = ($resource + "/.default")
    $appscopes = New-Object System.Collections.ObjectModel.Collection["string"]
    foreach ($s in $scopes) {
    $appscopes.Add($s)
    }
    #Build App and Set RedirectURI
    $BuiltApp = $ConfidentialClient.Build()
    $BuiltApp.RedirectUri = $RedirectUri
    #Execute Token ASync
    $GetToken = $BuiltApp.AcquireTokenForClient($appscopes)
    $AuthResult = $GetToken.ExecuteAsync()
    $waitcount = 0
    do{sleep -Milliseconds 100
        $waitcount ++}
    until($AuthResult.IsCompleted -eq $True -or $Watitcount -ge 50)
    if($AuthResult.IsFaulted -eq $true)
    {
        Write-Error $AuthResult.Exception.Message
        Write-Verbose $AuthResult.Exception.ToString()
    }
    else {
        return $AuthResult.Result
    }
    

}

function Get-AADTokenWithSecret
{
    [CmdletBinding()]
    param(
    [Parameter(Mandatory = $true)]
    $ClientID,
    [Parameter(Mandatory = $true)]
    $TenantId,
    [Parameter(Mandatory = $true)]
    $RedirectUri,
    [Parameter(Mandatory = $true)]
    [String]$Secret,
    [Parameter(Mandatory = $false)]
    $Resource = "https://graph.microsoft.com")


    #Create Confidential Client App
    $ConfidentialClient = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($clientid)
    #Configure Client with Auth Certificate
    [void]$ConfidentialClient.WithClientSecret($Secret)
    #Configure Client with Tenant Specific Authority
    [void]$ConfidentialClient.WithAuthority(("https://login.microsoftonline.com/" + $TenantID))
    #Define default scope
    $scopes = ($resource + "/.default")
    $appscopes = New-Object System.Collections.ObjectModel.Collection["string"]
    foreach ($s in $scopes) {
    $appscopes.Add($s)
    }
    #Build App and Set RedirectURI
    $BuiltApp = $ConfidentialClient.Build()
    $BuiltApp.RedirectUri = $RedirectUri
    #Execute Token ASync
    $GetToken = $BuiltApp.AcquireTokenForClient($appscopes)
    $AuthResult = $GetToken.ExecuteAsync()
    $waitcount = 0
    do{sleep -Milliseconds 100
        $waitcount ++}
    until($AuthResult.IsCompleted -eq $True -or $Watitcount -ge 50)
    if($AuthResult.IsFaulted -eq $true)
    {
        Write-Error $AuthResult.Exception.Message
        Write-Verbose $AuthResult.Exception.ToString()
    }
    else {
        return $AuthResult.Result
    }
    

}

function Get-AADTokenDelegated
{
    [CmdletBinding()]
    param(
    [Parameter(Mandatory = $true)]
    [string]$ClientID,
    [Parameter(Mandatory = $true)]
    [string[]]$Scopes)

    $PublicClient = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($ClientID)

    $appscopes = New-Object System.Collections.ObjectModel.Collection["string"]
    foreach ($s in $scopes) {
    $appscopes.Add($s)
    }
    $BuiltClientApp = $PublicClient.Build()
    $TokenAcquire = $BuiltClientApp.AcquireTokenInteractive($appscopes)
    $AuthResult = $TokenAcquire.ExecuteAsync()
    $waitcount = 0
    do{sleep -Milliseconds 100
        $waitcount ++}
    until($AuthResult.IsCompleted -eq $True -or $Watitcount -ge 5000)
    if($AuthResult.IsFaulted -eq $true)
    {
        Write-Error $AuthResult.Exception.Message
        Write-Verbose $AuthResult.Exception.ToString()
    }
    else {
        return $AuthResult.Result
    }

}