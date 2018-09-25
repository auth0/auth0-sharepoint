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

## Overriding protocol selection

The login page created upon installation (`/_login/{client_id}.aspx`) uses the request URL to build the redirect URL of the authentication request:

```cs
protected override void OnLoad(EventArgs e)
{
    [...]
    string redirectUri = HttpUtility.UrlEncode(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Authority) + "/_trust/");
    [...]
    Response.Redirect("https://" + domain + "/wsfed/" + clientId + "?wreply=" + redirectUri + "&wctx=" + state, true);
}
```

If your SharePoint server is behind a proxy server and the proxy does SSL termination, then the protocol in `HttpContext.Current.Request.Url` will be `http://` instead of `https://`, which will cause the created redirect URL to be incorrect. You can edit the login page to fix the protocol as in this example:

```cs
string redirectUri = HttpUtility.UrlEncode(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Authority).Replace("http://","https://") + "/_trust/");
```

The above example simply replaces `http://` with `https://` but you can use more advance logic if your proxy provides headers indicating the original protocol or URL.
