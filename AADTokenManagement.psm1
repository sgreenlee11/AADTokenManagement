<#
.SYNOPSIS
    Cmdlet for acquiring an Azure AD Token using a Certificate Private Key
.DESCRIPTION
    Cmdlet for acquiring an Azure AD Token using a Certificate Private Key. This is used for an application registration using Application permissions.
    The public key must up uploaded to Azure. The Certificate should be in the Windows Certificate Store for the Machine or Current User.
.EXAMPLE
    PS C:\>Get-AADTokenWithCert -ClientID "00000000-0000-0000-0000000000000" -TenantId "00000000-0000-0000-0000000000000" -RedirectUri "https://localhost" -CertificateThumbprint "0000000000000000000000000000000000000000000"
    Requests and Access token for the specified Client ID, using the specified Certificate Thumbprint. The Windows Certificate Store is searched for the certificate to use. 

.OUTPUTS
    Returns a Microsoft.Identity.Client.AuthenticationResult Object

.PARAMETER ClientID
    ClientID or Application ID from an Azure AD App Registration. Registration is managed via the Azure Port

.PARAMETER TenantID
    Tenant ID can be obtained for the App Registration Portal. Tenant ID is required when using Confidential Apps and Application Permissions

.PARAMETER RedirectURI
    Redirect URI configured via App Registration Portal. Does not need to be externally resolvable for this scenario.

.PARAMETER CertificateThumbprint
    Thumbprint of Certifacte used for authentication. The local certificate must contain the Private Key, and be present in one of the Windows Certificate Stores.
    The Public Key must be added to the Azure AD App Registration. A self-signed certificate can be used for this function. The Certificate must be tightly controlled.

.PARAMETER Resource
    Speficies the API Resource the token is requested for. The App registration must be granted permisisons to this resource. If this parameter is not specified,
    https://graph.microsoft.com is used.

#>
function Get-AADTokenWithCert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]$ClientID,
        [Parameter(Mandatory = $true)]
        [System.String]$TenantId,
        [Parameter(Mandatory = $true)]
        [System.Uri]$RedirectUri,
        [Parameter(Mandatory = $true)]
        [System.String]$CertificateThumbprint,
        [Parameter(Mandatory = $false)]
        [System.String]$Resource = "https://graph.microsoft.com")

    $OAuthCert = Get-ChildItem -Path "cert:\" -Recurse | Where-Object { $_.Thumbprint -match $CertificateThumbprint -and $_.HasPrivateKey -eq $true } | Select-Object -First 1
    If ($OAuthCert -eq $null) {
        Write-Error "Unable to Find OAuth Certificate in Local Stores"
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
    do {
        Start-Sleep -Milliseconds 100
        $waitcount ++
    }
    until($AuthResult.IsCompleted -eq $True -or $Watitcount -ge 50)
    if ($AuthResult.IsFaulted -eq $true) {
        Write-Error $AuthResult.Exception.Message
        Write-Verbose $AuthResult.Exception.ToString()
    }
    else {
        return $AuthResult.Result
    }
}

<#
.SYNOPSIS
    Cmdlet for acquiring an Azure AD Token using a Secret String
.DESCRIPTION
    Cmdlet for acquiring an Azure AD Token using a Secret String. This is used for an application registration using Application permissions.
    The Secret is generated in the Azure App Registration Portal. The Secret should stored in a secure manner, but is passed to the cmdlet as a string
.EXAMPLE
    PS C:\>Get-AADTokenWithSecret -ClientID "00000000-0000-0000-0000000000000" -TenantId "00000000-0000-0000-0000000000000" -RedirectUri "https://localhost" -Secret "0000000000000000000000000000000000000000000"
    Requests and Access token for the specified Client ID, using the specified Secret.

.OUTPUTS
    Returns a Microsoft.Identity.Client.AuthenticationResult Object

.PARAMETER ClientID
    ClientID or Application ID from an Azure AD App Registration. Registration is managed via the Azure Portal.

.PARAMETER TenantID
    Tenant ID can be obtained for the App Registration Portal. Tenant ID is required when using Confidential Apps and Application Permissions.

.PARAMETER RedirectURI
    Redirect URI configured via App Registration Portal. Does not need to be externally resolvable for this scenario.

.PARAMETER Secret
    String secret generated from the Azure App Registration Portal. Secrets should be stored in a secure manner. Using Certificates is the preferred approach.

.PARAMETER Resource
    Speficies the API Resource the token is requested for. The App registration must be granted permisisons to this resource. If this parameter is not specified,
    https://graph.microsoft.com is used.

#>

function Get-AADTokenWithSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]$ClientID,
        [Parameter(Mandatory = $true)]
        [System.String]$TenantId,
        [Parameter(Mandatory = $true)]
        [System.Uri]$RedirectUri,
        [Parameter(Mandatory = $true)]
        [System.String]$Secret,
        [Parameter(Mandatory = $false)]
        [System.String]$Resource = "https://graph.microsoft.com")


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
    do {
        sleep -Milliseconds 100
        $waitcount ++
    }
    until($AuthResult.IsCompleted -eq $True -or $Watitcount -ge 50)
    if ($AuthResult.IsFaulted -eq $true) {
        Write-Error $AuthResult.Exception.Message
        Write-Verbose $AuthResult.Exception.ToString()
    }
    else {
        return $AuthResult.Result
    }
    

}

<#
.SYNOPSIS
    Cmdlet for acquiring an Azure AD Token interactively. 
.DESCRIPTION
    Cmdlet for acquiring an Azure AD Token interactively. This is used for acquiring a token with Delegated Permissions. The application can be registered in
    Azure AD as a custom app, or be an Out of the Box app.
.EXAMPLE
    PS C:\>Get-AADTokenInteractive -ClientID "00000000-0000-0000-0000000000000" -TenantId "00000000-0000-0000-0000000000000" -Scopes "https://graph.microsoft.com/Contacts.ReadWrite" -UseDefaultRedirectUri $True
    
    Requests and Access token for the specified Client ID, for a single tenant app using a default Redirect URI. The Contact Read/Write Scope for the Microsoft
    Graph API is requested.

.OUTPUTS
    Returns a Microsoft.Identity.Client.AuthenticationResult Object

.PARAMETER ClientID
    ClientID or Application ID from an Azure AD App Registration. Registration is managed via the Azure Portal.

.PARAMETER TenantID
    Tenant ID can be obtained for the App Registration Portal. Tenant ID is required with interactive login for Apps that are deployed as Multi-Tenant.

.PARAMETER Scopes
    Specifies the permission scopes being requested. Scopes can be obtained from the Azure AD Portal after granting permisisons to an App Registration.

.PARAMETER UseDefaultRedirectUri
    Specifies whether or not to send the default Redirect URI as described here - https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-client-application-configuration.
    For simplicty it is easiest to configure the Recirect URI in your App Registration to use this value.
#>
function Get-AADTokenInteractive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]$ClientID,
        [Parameter(Mandatory = $true)]
        [System.String[]]$Scopes,
        [Parameter(Mandatory = $false)]
        [System.String]$TenantID,
        [Parameter(Mandatory = $false)]
        [Boolean]$UseDefaultRedirectURI = $False
    )

    $PublicClient = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($ClientID)
    if ($TenantID) {
        [void]$PublicClient.WithAuthority(("https://login.microsoftonline.com/" + $TenantID))
    }
    If ($UseDefaultRedirectURI -eq $true) {
        $PublicClient.WithDefaultRedirectUri()
    }
    $appscopes = New-Object System.Collections.ObjectModel.Collection["string"]
    foreach ($s in $scopes) {
        $appscopes.Add($s)
    }
    $BuiltClientApp = $PublicClient.Build()
    $TokenAcquire = $BuiltClientApp.AcquireTokenInteractive($appscopes)
    $AuthResult = $TokenAcquire.ExecuteAsync()
    $waitcount = 0
    do {
        sleep -Milliseconds 100
        $waitcount ++
    }
    until($AuthResult.IsCompleted -eq $True -or $Watitcount -ge 5000)
    if ($AuthResult.IsFaulted -eq $true) {
        Write-Error $AuthResult.Exception.Message
        Write-Verbose $AuthResult.Exception.ToString()
    }
    else {
        return $AuthResult.Result
    }

}