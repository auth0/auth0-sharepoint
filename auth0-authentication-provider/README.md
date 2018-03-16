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

## Customizing the Login Page

The Authentication Provider uses Universal Login to authenticate users. You can learn how to customize it by reading [this document](https://auth0.com/docs/hosted-pages/login).

## Updating from Previous Versions

Previous versions of the Authentication Provider used [Lock v9](https://auth0.com/lock) embedded in the Sharepoint Login page. Lock v9 is not longer supported.

To upgrade to the Universal Login page, you will need to manually update the existing login pages in your Sharepoint installation. Those can be found in the <Program Files>\Common Files\microsoft shared\Web Server Extensions\<Sharepoint Version>\TEMPLATE\IDENTITYMODEL\LOGIN, and are identified by the Sharepoint Client ID + ".aspx".

You will need to replace the contents of that file with the content in the [login.aspx](login.aspx) file, replacing the YOUR_AUTH0_DOMAIN and YOUR_CLIENT_ID strings with the values that can be found in the "Tutorial" tab of the [Sharepoint SSO Integration in the Auth0 Dashboard](https://manage.auth0.com/#/externalapps/)

```
    string domain = "YOUR_AUTH0_DOMAIN";
    string clientId = "YOUR_CLIENT_ID";
```

If you need to provide a way for users to log-in directly to Sharepoint using Windows Authentication, you will need to customize the login page to include a link to the Sharepoint Login page, usually http://<Sharepoint Site>/_windows/default.aspx?ReturnUrl=/_layouts/15/Authenticate.aspx. You can do it with the following code:
 
 ```
lock.on('signin ready', function() {
  $('.auth0-lock-tabs-container').
      after('<div><p class="auth0-lock-alternative" style="padding:5px 0;">' + 
            '<a class="auth0-lock-alternative-link" href="http://<Sharepoint Site>/_windows/default.aspx?ReturnUrl=/_layouts/15/Authenticate.aspx">' + 
            'Login with Windows Authentication'+
            '</a>'+ 
            </p><p><span>or</span></p></div>');
});
```
