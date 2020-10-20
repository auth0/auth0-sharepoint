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
    $sharepointVersion = GetSharePointVersion
    Switch ($sharepointVersion)
    {
        '2010' 
            {
                Log "Downloading Claims Provider solution for SP2010..."
                $webclient.DownloadFile("https://cdn.auth0.com/sharepoint/sp2010/Auth0.ClaimsProvider.wsp", "$modulePath\Auth0.ClaimsProvider.wsp")
                break;}
        '2013' 
            {
                Log "Downloading Claims Provider solution for SP2013..."
                $webclient.DownloadFile("https://cdn.auth0.com/sharepoint/sp2013/Auth0.ClaimsProvider.wsp", "$modulePath\Auth0.ClaimsProvider.wsp")
                break;}
        '2016' 
            {
                Log "Downloading Claims Provider solution for SP2016..."
                $webclient.DownloadFile("https://cdn.auth0.com/sharepoint/sp2016/Auth0.ClaimsProvider.wsp", "$modulePath\Auth0.ClaimsProvider.wsp")
                break;}
        default 
            {
                 LogError "Sharepoint version " + sharepointVersion + " is not supported by this script. ";
                break;}
        
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
