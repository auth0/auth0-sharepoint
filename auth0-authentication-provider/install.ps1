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

# Download module
Log "Downloading module..."
$webclient = new-object net.webclient
$webclient.DownloadString("https://raw.githubusercontent.com/auth0/auth0-sharepoint/master/auth0-authentication-provider/auth0.psm1") | Out-File "$modulePath\Auth0.psm1"
    
# Download claims provider.  
$isSP2013 = IsSharePoint2013
If ($isSP2013) {
    Log "Downloading Claims Provider solution for SP2013..."
    $webclient.DownloadFile("https://github.com/auth0/auth0-sharepoint/releases/download/sp2013-1.1.0/Auth0.ClaimsProvider.wsp", "$modulePath\Auth0.ClaimsProvider.wsp")
} Else {
    Log "Downloading Claims Provider solution for SP2010..."
    $webClient.DownloadFile("https://github.com/auth0/auth0-sharepoint/releases/download/sp2010-1.0.1.301/Auth0.ClaimsProvider.wsp", "$modulePath\Auth0.ClaimsProvider.wsp")
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