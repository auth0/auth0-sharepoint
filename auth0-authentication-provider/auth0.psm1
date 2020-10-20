# Globals.
$modulesPath = ($env:PSModulePath -Split ";")[0]
$modulePath = "$modulesPath\Auth0"
$identityTokenIssuerName = "Auth0"
$loginPageResourceUrl = "https://cdn.auth0.com/sharepoint/login.aspx"
$claimsProviderInternalName = "Auth0FederatedUsers"
  
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Output logs.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
$logsPath = [io.path]::combine($modulePath, 'auth0-sharepoint.log')
If (Test-Path $logsPath){
    Remove-Item $logsPath
}
$transcriptPath = [io.path]::combine($modulePath, 'auth0-sharepoint-output.log')
If (Test-Path $transcriptPath){
    Remove-Item $transcriptPath
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Log informational message.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function Log([string]$msg)
{
    $now = [datetime]::Now.ToString("HH:mm:ss")
    Write-Host " ", $now, " - ", $msg
    Add-Content $logsPath "$now - DEBUG: $msg`n"
} 

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Log error message.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
$hasErrors = $false
function LogError([string]$msg)
{
    $now = [datetime]::Now.ToString("HH:mm:ss")
    Write-Host -Fore Red " ", $now, " - ", $msg
    Add-Content $logsPath "$now - ERROR: $msg`n"
    $hasErrors = $true
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Log success message.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function LogSuccess([string]$msg)
{
    $now = [datetime]::Now.ToString("HH:mm:ss")
    Write-Host -Fore Green " ", $now, " - ", $msg
    Add-Content $logsPath "$now - INFO: $msg`n"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Get the SharePoint Version.
# Please note that this function works for Sharepoint 2010-2016.
# It must be updated to support Sharepoint 2019
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function GetSharePointVersion()
{
    $SPFarm = Get-SPFarm
    $number = $SPFarm.BuildVersion.Major

 Switch ($number)
    {
        14 {$version ='2010';break}
        15 {$version ='2013';break}
        16 {$version ='2016';break} # might not distinguish between 2016 & 2019 because major build  
                                    # version is the same. 
        default {$version = '0'}
    }

    Return $version

}



# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Send Result.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function SendResult {
	param (
		[string]$file = $(throw "File is required."),
		[string]$auth0Domain = $(throw "Domain is required. E.g.: mycompany.auth0.com"),
		[string]$method = $(throw "Method name is required. E.g.: Enable-Auth0"),
		[string]$resultLevel = "verbose"
	)
	
	try {
		$result = Get-Content $file | Out-String
		$result = $result.replace('\', '\\').replace('"', "'").replace("`r", "\r").replace("`n", "\n").replace("`t", "\t")
		$json = "{ `"app`": `"sharepoint`", `"level`": `"$resultLevel`", `"message`": `"$method`", `"description`": `"$result`" }"

		$url = "https://$auth0Domain/drwatson"
		$webclient = New-Object System.Net.WebClient
		$webclient.Headers.Add("Content-Type", "application/json")
		$webclient.UploadStringAsync($url, $json)
	}
	catch [system.exception] { }
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Resize the current window
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function ResizeWindow() {
	try {
        $pshost = get-host
        $maxWS = $pshost.UI.RawUI.Get_MaxWindowSize()
        $ws = $pshost.ui.RawUI.WindowSize
        if ($maxws.width -ge 85) { 
            $ws.width = 85 
        }
        else { 
            $ws.width = $maxws.width 
        }

        if ($maxws.height -ge 42) { 
            $ws.height = 42 
        }
        else { 
            $ws.height = $maxws.height 
        }
        
        $pswindow = $pshost.ui.rawui
        $pswindow.buffersize = $ws
        $pswindow.windowsize = $ws
	}
	catch [system.exception] { }
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Download Federation Metadata
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function GetFederationMetadata([string]$url)
{
	Write-Verbose "Downloading Federation Metadata from $url."
    
	$webclient = New-Object System.Net.WebClient
	$data = $webclient.DownloadData($url);
	$ms = new-object io.memorystream(,$data);
	$ms.Flush();
	$ms.Position = 0;
	$fedMetadata = new-object XML
	$fedMetadata.Load($ms)
	Return $fedMetadata
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Get Certificate.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function GetCertificate([xml]$fedMetadata) {
	$ns = @{xsi = 'http://www.w3.org/2001/XMLSchema-instance'}
	$roleDescriptor = Select-Xml "//*[@xsi:type[contains(.,'SecurityTokenServiceType')]]" $fedMetadata -Namespace $ns
	if (-Not $roleDescriptor) {
		LogError "The <RoleDescriptor> element with xsi:type='fed:SecurityTokenServiceType' was not found";
	}

	Return $roleDescriptor.Node.KeyDescriptor.KeyInfo.X509Data.X509Certificate
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Update Login Url.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function UpdateLoginUrlFromWebConfig([string]$webAppUrl, [string]$loginUrl) {
	Log "Updating web.config: /configuration/system.web/authentication/forms.loginUrl: '$loginUrl'"
	
	$webApp = GetWebApp ($webAppUrl)
	$webApp.WebConfigModifications.Clear()
	$webApp.Update();
	
	# Create SPWebConfigModification.
	$configModFormsAuthN = New-Object Microsoft.SharePoint.Administration.SPWebConfigModification
	$configModFormsAuthN.Path = "/configuration/system.web/authentication/forms"
	$configModFormsAuthN.Name = "loginUrl"
	$configModFormsAuthN.Sequence = 0
	$configModFormsAuthN.Type = 1 # Ensure Attribute
	$configModFormsAuthN.Value = $loginUrl
	
	# Apply SPWebConfigModification
	$webApp.WebConfigModifications.Add($configModFormsAuthN)
	$webApp.Update();
	$webApp.Parent.ApplyWebConfigModifications()
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Get the web application.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function GetWebApp([string]$webAppUrl) {
	if (-not $webAppUrl.EndsWith("/")) { 
		$webAppUrl += "/" 
	}
  
    Log "Looking for SPWebApplication: $webAppUrl"
	
	$webApp = Get-SPWebApplication | where { $_.Url -eq $webAppUrl }
	if ($webApp -Eq $null) {
		$apps = ""
		Get-SPWebApplication | foreach { $apps = $apps + "`r`n Name: " + $_.DisplayName + " Url: " + $_.Url; }
		LogError "There is no SharePoint application at this url '$webAppUrl'. The existing applications are: `r`n $apps`r`n" 
	}
	else {
		LogSuccess "Web Application loaded."
	}
	
	Return $webApp
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Validate the environment.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function ValidateEnvironment() {
	if ((Get-PSSnapin -Name Microsoft.Sharepoint.Powershell -Registered -ErrorAction SilentlyContinue) -eq $null) {
		LogError "This PowerShell script requires the Microsoft.Sharepoint.Powershell Snap-In. Try executing it from the SharePoint 2010."
		Return $false
	}

	if ((Get-PSSnapin -Name Microsoft.Sharepoint.Powershell -ErrorAction SilentlyContinue) -eq $null) {
		Log "Adding Microsoft.Sharepoint.Powershell Snapin."
		Add-PSSnapin Microsoft.Sharepoint.Powershell
	}

	$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
		LogError "This PowerShell script requires Administrator privileges. Try opening a PowerShell console by doing right click -> 'Run as Administrator'"
		Return $false
	}

	if ((Get-SPShellAdmin -ErrorAction SilentlyContinue) -eq $null) {
		LogError "This PowerShell script requires privileges to execute SharePoint CmdLets. Try adding the user '$($currentPrincipal.Identity.Name)' as SPShellAdmin. To do this run the following command Add-SPShellAdmin $($currentPrincipal.Identity.Name)"
        Return $false
	}
	
	Return $true
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# CmdLet: Enable Auth0 authentication.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function Enable-Auth0 {
	[CmdletBinding()]
	Param
	(
		[string]$auth0Domain = $(throw "Domain is required. E.g.: mycompany.auth0.com"),
		[string]$clientId = $(throw "Client id is required and it can be found in the dashboard"),
		[string]$webAppUrl = $(throw "SharePoint Web Application URL is required. E.g.: http://sp2010app"),
		[string]$identifierClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		# Claims to Map. Format: <DisplayName>|<ClaimType>
		[string[]]$claims = "Email Address|http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", 
        # Signing certificate (optional)
        [string]$certPath,
        # Path to certificates in the chain
		[string[]]$additionalCertPaths,  
		[switch]$allowWindowsAuth = $false
	)
	ResizeWindow

    if ($PSBoundParameters['Verbose']) { 
        $resultLevel = "verbose" 
    } else { 
        $resultLevel = "info" 
    }

    Write-Host ""
    Write-Host "  [Auth0] Enabling Auth0 authentication for: $webAppUrl"
    Write-Host ""
	
    # Login page.    
	$redirectionUrl = "~/_login/$clientId.aspx"  
    $version = GetSharepointVersion

    Switch ($version)
    {
        "2010" {$webServerExtensionVersion ="14";break}
        "2013" {$webServerExtensionVersion ="15";break}
        "2016" {$webServerExtensionVersion ="16";break} # might not distinguish between 2016 & 2019 because major build  
                                                        # version is the same. 
        default {$webServerExtensionVersion = "0"}
    }


	$loginPageFolder =  "$env:ProgramFiles\Common Files\Microsoft Shared\Web Server Extensions\$webServerExtensionVersion\TEMPLATE\IDENTITYMODEL\LOGIN"
	
    # WS-Federation.
	$realm = "urn:$clientId"
	$signInUrl = "https://$auth0Domain/wsfed"
	$fedLoginUrl = "https://$auth0Domain/wsfed/$clientId"
	$fedMetadataUrl = "http://$auth0Domain/wsfed/$clientId/FederationMetadata/2007-06/FederationMetadata.xml"

	# Constants.
	$certName = "auth0.cer"
	$reservedClaimTypes = @(
    	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", 
    	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");

	Write-Verbose "SharePoint Version: $spversion"

	if ($additionalCertPaths) {
		$additionalCertPaths = $additionalCertPaths | % { Resolve-Path $_ }
	}

	if (-Not $webAppUrl.EndsWith("/")) { 
		$webAppUrl += "/" 
	}

    # Validate.
    $valid = ValidateEnvironment
    if ($valid -eq $false) {
        Return
    }

	# Get the web application.
	$webApp = GetWebApp ($webAppUrl)
	if (-Not $webApp) {
		Return
	}

     ## Start recording output.
	Start-Transcript -Path $transcriptPath | Out-Null

	# Ensure that identifierClaimType is part of claims array.
	if (!($claims -like "*|" + $identifierClaimType)) {
		$claims += "Identifier|" + $identifierClaimType
	}

	# Validate claims array.
	foreach ($c in $claims) {
		$ct = $c.Split("|")[1];
		if ($reservedClaimTypes -contains $ct) {
			LogError "SharePoint reserved claim type $ct can't be used."
			Return
		}
	}

	# Get the signing certificate.
    	$fedMetadata = ""
    	If (Test-Path("FederationMetadata.xml")) {
    	   Log "Using local FederationMetadata file."
    	   $fedMetadata = Get-Content FederationMetadata.xml	
    	}
    	Else {
    	  Log "Downloading from: $fedMetadataUrl"
          $fedMetadata = GetFederationMetadata($fedMetadataUrl)
    	}
	
	GetCertificate($fedMetadata) | Set-Content $certName
	$certPath = Resolve-Path $certName
	$signingCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
	$tempCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
	$certs = @()
	$certs += $tempCert

	# Get the root certificate.
	while ($tempCert.Issuer -ne $tempCert.Subject) {
		$rootCertFound = $false
		foreach ($additionalCertPath in $additionalCertPaths) {
			$additionalCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($additionalCertPath)
			if ($additionalCert.Subject -eq $tempCert.Issuer) {
				$rootCertFound = $true
				break
			}
		}
		if (-Not $rootCertFound) {
			LogError "The certificate trust chain is incomplete. The certificate with the following SubjectName: $($tempCert.Issuer) was not found on the additional certificates parameter. Make sure you are including the whole trust chain path public keys in the additionalCertPaths parameter"
		  Return
		}
		$certs += $additionalCert
		$tempCert = $additionalCert
	}

	Log "Certificates: $certs"

	# Claims Mapping.
    Log "Claims Mapping:"
    
	$mappings = @()
	foreach ($newClaimMapping in $claims) {
		$displayName = $newClaimMapping.Split("|")[0]
		$claimType = $newClaimMapping.Split("|")[1]
	  
		Log " > Claim: $displayName | $claimType"	
		$mappings += New-SPClaimTypeMapping -IncomingClaimType $claimType -IncomingClaimTypeDisplayName $displayName -SameAsIncoming
	}

	# Add Auth0 as Trusted Identity Token issues.
	$spti = $null
	$existingIdP = Get-SPTrustedIdentityTokenIssuer
	if ($existingIdP -ne $null) {
		foreach ($idp in $existingIdP) {
			if ($idp.Name -eq $identityTokenIssuerName) {
				$spti = $idp
				break
			}
		}
	}

    # Create issuer.
	$uri = New-Object System.Uri($webAppUrl)
	if ($spti -eq $null) {
		Log "Creating the SPTrustedIdentityTokenIssuer: '$identityTokenIssuerName'."

		$spti = New-SPTrustedIdentityTokenIssuer -Name $identityTokenIssuerName -Description "Auth0 Federation Hub" -Realm $realm -ImportTrustCertificate $signingCert -SignInUrl $signInUrl -ClaimsMappings $mappings -IdentifierClaim $identifierClaimType
		$spti.DefaultProviderRealm = "";
		$spti.ProviderRealms.add($uri, $realm)
		$spti.Update()
	}
	else {
		Log "SPTrustedIdentityTokenIssuer '$identityTokenIssuerName' already exists."
      
		$spti = Get-SPTrustedIdentityTokenIssuer $identityTokenIssuerName
		$previouslyInexistentMappings = @()

		foreach ($claimMapping in $mappings) {
			$isRepeated = $false
			foreach ($claimTypeInformation in $spti.ClaimTypeInformation) {   
				if ($claimMapping.DisplayName -eq $claimTypeInformation.DisplayName) {
					if ($claimMapping.InputClaimType -ne $claimTypeInformation.InputClaimType) {      
						Log " ! ClaimType '$($claimTypeInformation.DisplayName)' already in use."
					}
					$isRepeated = $true
				}
				else {
					if ($claimMapping.InputClaimType -eq $claimTypeInformation.InputClaimType) {
						Log " ! ClaimType '$($claimTypeInformation.DisplayName)' already in use."
					}           
				}
			}
			if ($isRepeated -ne $true) {
				$previouslyInexistentMappings += $claimMapping
			}
		}

        Log "Adding claims..."
		foreach ($claimMapping in $previouslyInexistentMappings) {
			Log " > Adding ClaimType $claimMapping.InputClaimType"
			$spti.ClaimTypes.Add($claimMapping.InputClaimType)
			$spti.Update()
			
			Add-SPClaimTypeMapping -Identity $claimMapping -TrustedIdentityTokenIssuer $spti
			Log "   Added claim mapping: '$($claimMapping.DisplayName)' '$($claimMapping.InputClaimType)'."
		}

		$isStsConfigured = $false
		$existingAuthProv = Get-SPAuthenticationProvider -webapplication $webApp -zone "Default"
		foreach ($authProv in $existingAuthProv) {
			if ($authProv.LoginProviderName -eq $identityTokenIssuerName) {
				Log "$identityTokenIssuerName is configured for $webAppUrl."
				$isStsConfigured = $true
				Break
			}
		}

		$spti.SigningCertificate = $signingCert
		$spti.ProviderUri = $signInUrl
		$spti.Update()
	  
		if (-Not $isStsConfigured)  {
			if ($spti.ProviderRealms.ContainsKey($webApp.Url)) { 
				$spti.ProviderRealms.Remove($webApp.Url) 
			} 
		}
		else {
			Log "ProviderRealms check for '$($webApp.Url)' and not: '$realm'." 
			$realmChanged = $spti.ProviderRealms.ContainsKey($webApp.Url) -and -not $spti.ProviderRealms.ContainsValue($realm);
			if ($realmChanged) {
				Log " > Realm changed: '$($realmChanged)'"
				$spti.ProviderRealms.Remove($webApp.Url)
			}
		}
		  
		$spti.DefaultProviderRealm = "";
		try {
			Log "Adding ProviderRealms '$realm' to the webapp '$uri'" 
			$spti.ProviderRealms.add($uri, $realm)
			$spti.Update()
		}
		catch { }
	}

	foreach ($providerRealm in $spti.ProviderRealms.GetEnumerator()) {
		Write-Verbose "Configured provider realm. Uri: '$($providerRealm.Key)' - Realm: '$($providerRealm.Value)'"
	}

	# Update Web Application to use claims authentication.
    Log "Checking that $webAppUrl has claims-based authentication configured."

    # Update Web  Application.
	$webApp = Get-SPWebApplication | Where { $_.Url -eq $webAppUrl }
	if ($webApp.UseClaimsAuthentication -Ne 1) {
		Write-Verbose "Configuring claims-based authentication for $webAppUrl."
		$webApp.UseClaimsAuthentication = 1
		$webApp.Update()
		$webApp.ProvisionGlobally()
	}

	# Configure Auth0.
	if ($isStsConfigured -ne $true) {
		[array] $authProviders = $existingAuthProv

        Log "Adding $identityTokenIssuerName to $webAppUrl as authentication provider. This can take a few minutes!"
		Set-SPWebApplication $webApp -AuthenticationProvider ($authProviders + $spti) -zone "Default"
	}
	
	# Check for Windows Authentication as authentication provider.
	$existingAuthProv = Get-SPAuthenticationProvider -webapplication $webApp -zone "Default"
	$isWindowsAuthConfigured = $false
	
	Log "Configured Authentication Providers:"
	foreach ($authProv in $existingAuthProv) {
		Log " > DisplayName: '$($authProv.DisplayName)', ClaimProviderName: '$($authProv.ClaimProviderName)', UseWindowsIntegratedAuthentication: '$($authProv.UseWindowsIntegratedAuthentication)'"
		if (($isWindowsAuthConfigured -eq $false) -and ($authProv.ClaimProviderName -eq 'AD')) {
			$isWindowsAuthConfigured = $true
		}
	}
	
    # Windows Authentication.
	if ($allowWindowsAuth) {
		if ($isWindowsAuthConfigured -eq $false) {
			Log "Enabling Windows Authentication as Authentication Provider."
			[array] $authProviders = $existingAuthProv
			$windows = New-SPAuthenticationProvider
			Set-SPWebApplication $webApp -AuthenticationProvider ($authProviders + $windows) -zone "Default"
			$isWindowsAuthConfigured = $true
		}
		else {
			Log "Windows Authentication is already configured as Authentication Provider."
		}
	}

	# Add STS certificate and its certificate chain as trusted.
	$existingTrustedRootAuth = Get-SPTrustedRootAuthority
	foreach ($tempCert in $certs) {
		$certName = ([regex]'CN=([^,]+)').matches($tempCert.Subject) | foreach {$_.Groups[1].Value}
		
		Log "Checking if certificate $certName exists in SP trusted root."  
		$trustedRootAuthExists = $false
		
		foreach ($trustedRootAuth in $existingTrustedRootAuth) {
			if ($trustedRootAuth.Name -Eq $certName) {
				Log " > Certificate $certName exists in SP trusted root."  
				$trustedRootAuthExists = $true
				break
			}
		}
		
		if ($trustedRootAuthExists -Ne $true) {
			Log "Certificate $certName does not exist in SP trusted root. Adding certificate $certName to SP trusted root."
			New-SPTrustedRootAuthority -name $certName -Certificate $tempCert
		}
	}

    If (-Not (Test-Path($loginPageFolder))) {
	    LogError "The SharePoint folder '$loginPageFolder' could not be found"
	    Return
    }

    # Create login page.
    If (-Not (Test-Path("$loginPageFolder\$clientId.aspx"))) {
    	Log "Creating login page."
    	
    	$loginPageContents = ""
    	If (Test-Path("login.aspx")) {
    	   Log "Using local file."
    	   $loginPageContents = Get-Content login.aspx	
    	}
    	Else {
    	  Log "Downloading from: $loginPageResourceUrl"
          $loginPageContents = (new-object net.webclient).DownloadString($loginPageResourceUrl)
    	}

        $loginPageContents  | foreach { $_ -replace "YOUR_AUTH0_DOMAIN", "$auth0Domain" } | foreach { $_ -replace "YOUR_CLIENT_ID", "$clientId" } | foreach { if (!$allowWindowsAuth) { $_ -replace 'var allowWindowsAuth = true;', 'var allowWindowsAuth = false;' } else { $_ } } | Set-Content .\"$clientId.aspx"
  
        # Copy the file.
        Copy-Item "$clientId.aspx" "$loginPageFolder\$clientId.aspx"
    } Else {
        Log "Login page already exists."
    }
	
	# Set ClaimsAuthenticationRedirectionUrl
    Log "Setting login url: $redirectionUrl"
	$webApp = GetWebApp ($webAppUrl)
	$settings = $webApp.IisSettings.get_item("Default");
	$settings.ClaimsAuthenticationRedirectionUrl = $redirectionUrl;
	$webApp.Update();
	
	# Backup web.config
	$webConfigPath = [io.path]::combine($settings.Path.FullName, "web.config");
	$webconfig = [xml](get-content $webConfigPath);
	$webconfig.Save($webConfigPath + ".backup");
	
	# Update login url.
	UpdateLoginUrlFromWebConfig -webAppUrl $webAppUrl -loginUrl $redirectionUrl

    # Done.
    LogSuccess "SharePoint Web Application '$webAppUrl' configured successfully with $identityTokenIssuerName."
    LogSuccess " > Auth0 has been enabled for the Default zone. You can manually add it to other zones through Central Admin."
	Write-Host ""
    
    # Stop recording.
	Stop-Transcript | Out-Null
	
	# Report logs.
	if ($error.count -gt 0) { 
        $resultLevel = "error" 
    }
	SendResult -auth0Domain $auth0Domain -method "Enable-Auth0" -resultLevel $resultLevel -file $transcriptPath
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# CmdLet: Disable Auth0 authentication.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function Disable-Auth0 {
	[CmdletBinding()]
	Param ([string]$webAppUrl = $(throw "SharePoint Web Application url is required. E.g.: http://sp2010app"))
    ResizeWindow

    Write-Host ""
    Write-Host "  [Auth0] Disabling Auth0 authentication for: $webAppUrl"
    Write-Host ""
    
    # Fix Web Application url.
	if (-Not $webAppUrl.EndsWith("/")) { 
		$webAppUrl += "/" 
	}

    # Validate.
    $valid = ValidateEnvironment
    if ($valid -eq $false) {
        Return
    }

	# Get the web application.
	$webApp = GetWebApp ($webAppUrl)
	if (-Not $webApp) {
		Return
	}

    # Remove authentication provider from all zones.
    Log "Processing zones..."
    foreach ($zoneName in $webApp.IisSettings.Keys)
    {   
        $zone = $webApp.IisSettings[$zoneName]
        $webSiteName = $zone.ServerComment
        Log " > ${zoneName}: $webSiteName"

        # Need an update?
        $requireUpdate = $false
        Get-SPAuthenticationProvider -WebApplication $webapp.Name -Zone:$zoneName | ForEach-Object { 
            If ($_.ClaimProviderName -eq "Auth0FederatedUsers") {
                $requireUpdate = $true
            }
            If ($_.LoginProviderName -eq "Auth0") {
                $requireUpdate = $true
            }
	    }

        # Update.
        If ($requireUpdate -Eq $true) {
            Log "   Reverting to Windows Authentication for $zoneName (this can take a few minutes)."
            $windows = New-SPAuthenticationProvider
            Set-SPWebApplication $webApp -AuthenticationProvider $windows -zone $zoneName
        }
    }


    # Removing issuer.
    Log "Removing issuer."
	$all = Get-SPTrustedIdentityTokenIssuer
	if (-Not($all -Eq $null)) {
		$spti = Get-SPTrustedIdentityTokenIssuer $identityTokenIssuerName
		if (-Not($spti -Eq $null)) {
		
			$spti.ProviderRealms.Remove($webAppUrl);
			if ($spti.ProviderRealms.Count -Eq 0) {
                Log "Removing SPTrustedIdentityTokenIssuer: '$identityTokenIssuerName'"
				$spti | Remove-SPTrustedIdentityTokenIssuer -Confirm:$false
			}
		}
	}
	
	# Clear redirect url.
    Log "Clear Redirect Url."
	$webApp = GetWebApp ($webAppUrl)
	$settings = $webApp.IisSettings.get_item("Default");
	$settings.ClaimsAuthenticationRedirectionUrl = "";
	$webApp.Update()
	
	# Create backup.
    Log "Backing up web.config."
	$source = [io.path]::combine($settings.Path.FullName, "web.config")
	$destination = [io.path]::combine($settings.Path.FullName, "web.config.auth0")
	Copy-Item $source $destination
	
	# Update login url.
	UpdateLoginUrlFromWebConfig -webAppUrl $webAppUrl -loginUrl "~/_login/default.aspx"
	
    # Done.
	Log "The login page now is the default page."
	LogSuccess "Auth0 has been uninstalled from SharePoint Web Application '$webAppUrl'."
    Write-Host ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# CmdLet: Show the Auth0 Trusted Identity Token Issuer.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function List-Auth0 {
	[CmdletBinding()]
	Param ()
    ResizeWindow

    Write-Host ""
    Write-Host "  [Auth0] Applications configured with Auth0"
    Write-Host ""
    
    # Validate.
    $valid = ValidateEnvironment
    if ($valid -eq $false) {
        Return
    }
    
    # Removing issuer.
	$all = Get-SPTrustedIdentityTokenIssuer
	if (-Not($all -Eq $null)) {
		$spti = Get-SPTrustedIdentityTokenIssuer $identityTokenIssuerName
		if (-Not($spti -Eq $null)) {
            $realms = $spti.ProviderRealms
			if ($spti.ProviderRealms.Count -Eq 0) {
                Log "Trusted Identity Token Issues enabled but not installed on any of the applications.."
			} else {
                Log "Enabled applications:"
                foreach ($realm in $realms.GetEnumerator()) {
                  Log " > $realm"
                } 
            }
		} else {
            Log "Could not find the Auth0 Trusted Identity Token Issuers."
        }
	}
    else {
        LogError "Could not load the Trusted Identity Token Issuers."
    }
	
    # Done.
	Write-Host ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# CmdLet: Enable Auth0 CLaims Provider.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function Enable-ClaimsProvider {
	[CmdletBinding()]
	Param()
    ResizeWindow

    Write-Host ""
    Write-Host "  [Auth0] Enabling Claims Provider"
    Write-Host ""
      
    # Validate.
    $valid = ValidateEnvironment
    if ($valid -eq $false) {
        Return
    } 
    
    # Module Path
    Log "Module path: $modulePath"
  
    # WSP.
    $solutionName = "auth0.claimsprovider.wsp"
    $wspPath = "$modulePath\$solutionName"
    Log "Solution: $wspPath"
    
	$solution = Get-SPSolution $solutionName -ErrorAction SilentlyContinue

    # Auth0 not enabled.
	if (-Not (Get-SPTrustedIdentityTokenIssuer Auth0 -ErrorAction SilentlyContinue)) {
        LogError "Auth0 is not enabled. Please use the Enable-Auth0 command or read the documentation: https://docs.auth0.com/integrations/sharepoint"
        Return
	}

    # Add Claims Provider.
	if (-Not $solution -Or -Not $solution.Added) {
		Log "Adding Claims Provider solution."
		$solution = Add-SPSolution -LiteralPath $wspPath
	}

    # Install or update.
	if ($solution.DeploymentState -eq "NotDeployed") {
		Log "Installing Claims Provider solution. This can take a few minutes."
		Install-SPSolution -Identity $solution -GACDeployment
	}
	else {
		Log "Updating Claims Provider solution. This can take a few minutes"
		Update-SPSolution -identity $solution -LiteralPath $wspPath -GACDeployment
	}

	do { }
	while ((Get-SPSolution $solutionName).JobExists)
    
	try {
        Log "Disabling feature..."
        Disable-SPFeature -Identity "Auth0ClaimsProvider" -Confirm:$false -ErrorAction SilentlyContinue
	}
	catch [system.exception] {
        Log "Warning: Disabling the feature failed (maybe it was already disabled)"
    }
    
	try {
        Log "Enabling feature..."
        Enable-SPFeature -Identity "Auth0ClaimsProvider" -Confirm:$false -ErrorAction SilentlyContinue
	}
	catch [system.exception] {
        Log "Warning: Enabling the feature failed (maybe it was already enabled)"
    }

    # Update
	Log "Associating SP Trusted Identity Token Issuer (Auth0) with the Claims Provider ($claimsProviderInternalName)"
	$spti = Get-SPTrustedIdentityTokenIssuer -identity $identityTokenIssuerName 
	$spti.ClaimProviderName = $claimsProviderInternalName
	$spti.Update();
	
    # Done.
    LogSuccess "Done. Please, go to 'SharePoint Central Admin' -> 'Security':"
    LogSuccess " 1. Under General Security section, click on 'Configure Auth0 Claims Provider'"
    LogSuccess " 2. Set the required configuration parameters"
    Write-Host ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# CmdLet: Disable the Auth0 Claims Provider.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function Disable-ClaimsProvider {
	[CmdletBinding()]
	Param()

    Write-Host ""
    Write-Host "  [Auth0] Disabling Claims Provider"
    Write-Host ""
      
    # Validate.
    $valid = ValidateEnvironment
    if ($valid -eq $false) {
        Return
    }
     
	try {
        Log "Removing SPClaimProvider..."
        Remove-SPClaimProvider –Identity $claimsProviderInternalName -ErrorAction SilentlyContinue
	}
	catch [system.exception] {
        Log "Warning: Removing SPClaimProvider failed (maybe the provider was already removed)"
    }
    
	try {
        Log "Disabling feature..."
        Disable-SPFeature -Identity "Auth0ClaimsProvider" -Confirm:$false -ErrorAction SilentlyContinue
	}
	catch [system.exception] {
        Log "Warning: Disabling the feature failed (maybe it was already disabled)"
    }
	
    # Get the solution.
	$solutionName = "auth0.claimsprovider.wsp"
	$solution = Get-SPSolution $solutionName -ErrorAction SilentlyContinue
	if ($solution) {
		if ($solution.DeploymentState -ne "NotDeployed") {
			Log "Uninstalling Auth0 Claims Provider solution. This can take a few minutes."
			Uninstall-SPSolution -Identity $solutionName -Confirm:$false
			
			do { }
			while ((Get-SPSolution $solutionName).JobExists)
		}
		
  	    Log "Removing Auth0 Claims Provider solution. This can take a few minutes."
		Remove-SPSolution -Identity $solutionName -Confirm:$false
		
		do { }
		while (Get-SPSolution $solutionName -ErrorAction SilentlyContinue)
	}
    else {
        Log "Solution was already removed."
    }
  
    # Done.
    LogSuccess "Done."
    Write-Host ""
}


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# CmdLet: Update the Auth0 Claims Provider.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function Update-ClaimsProvider {
	[CmdletBinding()]
	Param()

    Write-Host ""
    Write-Host "  [Auth0] Update Claims Provider"
    Write-Host ""
      
    # Download claims provider.  
    $webclient = new-object net.webclient
    $sharepointVersion = GetSharepointVersion

    Switch ($sharepointVersion)
    {
        2010 {
                Log "Downloading Claims Provider solution for SP2010...";
                $webClient.DownloadFile("https://cdn.auth0.com/sharepoint/sp2010/Auth0.ClaimsProvider.wsp", "$modulePath\Auth0.ClaimsProvider.wsp");
                break;}
        2013 {
                Log "Downloading Claims Provider solution for SP2013...";
                $webclient.DownloadFile("https://cdn.auth0.com/sharepoint/sp2013/Auth0.ClaimsProvider.wsp", "$modulePath\Auth0.ClaimsProvider.wsp");
                break;}
        2016 {    
                Log "Downloading Claims Provider solution for SP2016..."
                $webclient.DownloadFile("https://cdn.auth0.com/sharepoint/sp2016/Auth0.ClaimsProvider.wsp", "$modulePath\Auth0.ClaimsProvider.wsp")
                break} # might not distinguish between 2016 & 2019 because the major build version is the same.
                                    
        default {LogError "Sharepoint version " + $sharepointVersion + " is not supported by this function."}
    }
  
    # Done.
    Disable-ClaimsProvider
    Enable-ClaimsProvider
}


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# CmdLet: Troubleshoot Auth0
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function Troubleshoot-Auth0 {
	[CmdletBinding()]
	Param()
    ResizeWindow

    Write-Host ""
    Write-Host "  [Auth0] Troubleshoot"
    Write-Host ""
    
    # Update
	Log "Identity Token Issuer Name: $identityTokenIssuerName"
	Log "Claim Provider Name: Auth0FederatedUsers"
    
	try {
	    $spti = Get-SPTrustedIdentityTokenIssuer -identity $identityTokenIssuerName -ErrorAction SilentlyContinue 
        if ($spti) {
            Log "SPTrustedIdentityTokenIssuer:"
            Log "  > Provider Uri: $($spti.ProviderUri)"
            Log "  > Provider Realms:"
            $spti.ProviderRealms
            Write-Host ""
            Log "  > Claim Types:"
            Write-Host ""
            $spti.ClaimTypes
            Write-Host ""
        }
	}
	catch [system.exception] {
        LogError "Error loading SPTrustedIdentityTokenIssuer"
    }

    Write-Host ""
    Log "Auth0 Features:"

    $features = (Get-SPFeature | Where {$_.DisplayName.Contains("Auth")})
    foreach ($feature in $features)
    {   
        Log "   > $($feature.Scope): $($feature.DisplayName) ($($feature.Id))"
    }

    If ($features.length -eq 0) {
        Log " > No Auth0 features installed."
    }

    Write-Host ""
    Log "SharePoint Web Applications":
    
    $webApps = Get-SPWebApplication
    foreach ($webApp in $webApps) {
        Log " > $($webApp.Name)"
        
        # Loop all zones.
        foreach ($zoneName in $webApp.IisSettings.Keys)
        {   
            $zone = $webApp.IisSettings[$zoneName]
            $webSiteName = $zone.ServerComment
            Log "   > Zone ${zoneName}: $webSiteName"

            # Need an update?
            Get-SPAuthenticationProvider -WebApplication $webapp.Name -Zone:$zoneName | ForEach-Object { 
                Log "     Claims Provider: $($_.ClaimProviderName)"
	        }
        }
    } 
    
    Write-Host ""
  	Log "Installed Claims Providers:"
    Get-SPClaimProvider | ForEach-Object {
		Log "  > $($_.TypeName) ('$($_.DisplayName)')"
		Log "    IsEnabled: $($_.IsEnabled)"
		Log "    $($_.AssemblyName)"
    }

    Write-Host ""  
	$solution = Get-SPSolution $solutionName -ErrorAction SilentlyContinue
	if ($solution) {
  	    Log " Claims Provider solution:"
		Log "  > Name: $($solution.Name)"
		Log "  > SolutionId: $($solution.SolutionId)"
		Log "  > Deployed: $($solution.Deployed)"
	}
    else {
        Log " Claims Provider is not installed."
    }
  
    Write-Host ""
    Log "Searching for Auth0 assemblies..."
    Get-ChildItem C:\Windows\assembly\GAC_MSIL -filter *.dll -recurse  | Where {$_.Name.Contains("Auth0")} | ForEach-Object { 
        Log " > $($_.Directory)"	       
    }
    Get-ChildItem C:\Windows\Microsoft.Net\assembly\GAC_MSIL -filter *.dll -recurse  | Where {$_.Name.Contains("Auth0")} | ForEach-Object { 
        Log " > $($_.Directory)"	
    }
    Log "Done."

    # Done.
	SendResult -auth0Domain "tenant.auth0.com" -method "Troubleshoot-Auth0" -resultLevel $resultLevel -file $logsPath
    Write-Host ""
}

# Export Modules.
Export-ModuleMember Enable-Auth0
Export-ModuleMember Disable-Auth0
Export-ModuleMember Enable-ClaimsProvider
Export-ModuleMember Disable-ClaimsProvider
Export-ModuleMember Update-ClaimsProvider
Export-ModuleMember Troubleshoot-Auth0

