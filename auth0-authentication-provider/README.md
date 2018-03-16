# Auth0 Authentication Provider for SharePoint 2010 / 2013

These are the installation scripts to configure Auth0 as an authentication provider in SharePoint. Every change made to this file will be published to the Auth0 CDN:

 - https://cdn.auth0.com/sharepoint/auth0.psm1
 - https://cdn.auth0.com/sharepoint/install.ps1
 - https://cdn.auth0.com/sharepoint/login.aspx

## Offline Installation

Depending on your environment your SharePoint Server might not have internet access. In that case the installation can also be done in offline mode. For this to work you'll need to download the following files to a folder on one of your SharePoint Servers and start the installation from that folder (following the tutorial in the Auth0 dashboard):

 - [auth0.psm1](https://cdn.auth0.com/sharepoint/auth0.psm1)
 - [install.ps1](https://cdn.auth0.com/sharepoint/install.ps1)
 - [login.aspx](https://cdn.auth0.com/sharepoint/login.aspx) (In some browsers you might need to right click and choose "Save As...")
 - FederationMetadata file: `https://{YOUR_AUTH0_DOMAIN}/wsfed/FederationMetadata/2007-06/FederationMetadata.xml`
