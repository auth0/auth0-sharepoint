# Auth0 SharePoint

This repository shows different ways of interacting with a SharePoint environment that has been configured with Auth0.

- [clientcontext-active-authentication](clientcontext-active-authentication): Active Authentication with Auth0 when talking to SharePoint using the ClientContext (API)
- [auth0-authentication-provider](auth0-authentication-provider): SharePoint PowerShell Module to connect SharePoint Web Applications with Auth0
- [auth0-claims-provider](auth0-claims-provider/src): Auth0 Claims Provider for SharePoint 2010 / 2013 

## Customizing the Login Page

The Authentication Provider uses Universal Login to authenticate users. You can learn how to customize it by reading [this document](https://auth0.com/docs/hosted-pages/login).

## Updating from Previous Versions

Previous versions of the Authentication Provider used [Lock v9](https://auth0.com/lock) embedded in the Sharepoint Login page. Lock v9 is not longer supported.

To upgrade to the Universal Login page, you will need to manually update the existing login pages in your Sharepoint installation. Those can be found in the <Program Files>\Common Files\microsoft shared\Web Server Extensions\<Sharepoint Version>\TEMPLATE\IDENTITYMODEL\LOGIN, and are identified by the Sharepoint Client ID + ".aspx".

You will need to replace the contents of that file with the content in the [login.aspx](auth0-authentication-provider\login.aspx) file, replacing the YOUR_AUTH0_DOMAIN and YOUR_CLIENT_ID strings with the values that can be found in the "Tutorial" tab of the [Sharepoint SSO Integration in the Auth0 Dashboard](https://manage.auth0.com/#/externalapps/)

```
    string domain = "YOUR_AUTH0_DOMAIN";
    string clientId = "YOUR_CLIENT_ID";
```

If you need to provide a way for users to log-in directly to Sharepoint using Windows Authentication, you will need to customize the login page to include a link to the Sharepoint Login page, usually http://<Sharepoint Site>/_windows/default.aspx?ReturnUrl=/_layouts/15/Authenticate.aspx. You can do it with the following code:
 
 ```js
lock.on('signin ready', function() {
  $('.auth0-lock-tabs-container').
      after('<div><p class="auth0-lock-alternative" style="padding:5px 0;">' + 
            '<a class="auth0-lock-alternative-link" href="http://<Sharepoint Site>/_windows/default.aspx?ReturnUrl=/_layouts/15/Authenticate.aspx">' + 
            'Login with Windows Authentication'+
            '</a>'+ 
            '</p><p><span>or</span></p></div>');
});
```

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free Auth0 Account

1. Go to [Auth0](https://auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
