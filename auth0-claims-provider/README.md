# This library is DEPRECATED

The features required by this library are no longer provided by Auth0 for new tenants.

# Auth0 Claims Provider for SharePoint 2010 / 2013

## Prerequisites

  - SharePoint Tools for Visual Studio
  - <a href="http://www.microsoft.com/en-us/download/details.aspx?id=17630" target="_blank">ILMerge</a>

## Development

First configure your SharePoint environment to use Auth0:

```ps1
iex ((new-object net.webclient).DownloadString("https://cdn.auth0.com/sharepoint/install.ps1"))
Enable-Auth0 -auth0Domain:"YOUR_DOMAIN.auth0.com" -clientId:"YOUR_CLIENT_ID" -webAppUrl:"http://YOUR_WEB_APP" -identifierClaimType:"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" -claims:@("Email|http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "Client ID|http://schemas.auth0.com/clientID", "Given Name|http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "Surname|http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "Picture|http://schemas.auth0.com/picture") -allowWindowsAuth
Enable-ClaimsProvider
```

  1. Open solution and enable "NuGet Package Restore"
  2. Compile solution
  3. Deploy from within Visual Studio

## Releasing

To create a new version build the WSP in Release mode on your machine and create a GitHub release: https://github.com/auth0/auth0-sharepoint/releases

The tag must include the SharePoint version, eg:

 - `sp2013-1.1.0`
 - `sp2010-1.0.1.301`

After the release has been created the release will be available on the Auth0 CDN:

 - https://cdn.auth0.com/sharepoint/sp2013/Auth0.ClaimsProvider.wsp
 - https://cdn.auth0.com/sharepoint/sp2010/Auth0.ClaimsProvider.wsp

## Documentation

For more information about <a href="http://auth0.com" target="_blank">auth0</a> visit our <a href="http://docs.auth0.com/" target="_blank">documentation page</a>.
