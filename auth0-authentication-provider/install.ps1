# Globals.
$modulesPath = ($env:PSModulePath -Split ";")[0]
$modulePath = "$modulesPath\Auth0"

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Log informational message.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function Log([string]$msg)
{
    $now = [datetime]::Now.ToString("HH:mm:ss")
    Write-Host " ", $now, " - ", $msg
} 

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Log error message.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function LogError([string]$msg)
{
    $now = [datetime]::Now.ToString("HH:mm:ss")
    Write-Host -Fore Red " ", $now, " - ", $msg
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: Log success message.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function LogSuccess([string]$msg)
{
    $now = [datetime]::Now.ToString("HH:mm:ss")
    Write-Host -Fore Green " ", $now, " - ", $msg
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
# Function: SharePoint 2013.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
function IsSharePoint2013 {
    $SPFarm = Get-SPFarm
    return $SPFarm.BuildVersion.Major -eq 15
}

Write-Host ""
Write-Host "  [Auth0] Installing Auth0 CmdLets for SharePoint"
Write-Host ""

# Create Module Directory
Log "Creating module directory..."
New-Item -Type Container -Force -path $modulePath | Out-Null

If (Test-Path("auth0.psm1")) {
    Log "Copying module to $modulePath."
    Copy-Item auth0.psm1 "$modulePath\Auth0.psm1"
}
Else {
    # Download module
    Log "Downloading module..."
    $webclient = new-object net.webclient
    $webclient.DownloadString("https://cdn.auth0.com/sharepoint/auth0.psm1") | Out-File "$modulePath\Auth0.psm1"
}

If (Test-Path("Auth0.ClaimsProvider.wsp")) {
    Log "Copying Claims Provider to $modulePath."
    Copy-Item Auth0.ClaimsProvider.wsp "$modulePath\Auth0.ClaimsProvider.wsp"
}
Else {
    # Download claims provider.  
    $isSP2013 = IsSharePoint2013
    If ($isSP2013) {
        Log "Downloading Claims Provider solution for SP2013..."
        $webclient.DownloadFile("https://cdn.auth0.com/sharepoint/sp2013/Auth0.ClaimsProvider.wsp", "$modulePath\Auth0.ClaimsProvider.wsp")
    } Else {
        Log "Downloading Claims Provider solution for SP2010..."
        $webClient.DownloadFile("https://cdn.auth0.com/sharepoint/sp2010/Auth0.ClaimsProvider.wsp", "$modulePath\Auth0.ClaimsProvider.wsp")
    }
}

# Remove Module
If (Get-Module "Auth0") { 
    Remove-Module "Auth0" 
}

# Install Module
Import-Module "$modulePath\Auth0.psm1"

# Done
LogSuccess "Auth0 PowerShell Module for SharePoint installed and imported!"
Write-Host ""
