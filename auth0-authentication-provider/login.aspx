<%@ Page Language="C#"%>
<script runat="server">

private static string GetParameterByName(string queryString, string name)
{
    System.Text.RegularExpressions.Regex r = new System.Text.RegularExpressions.Regex("[\\?&]" + name + "=([^&#]*)");
    System.Text.RegularExpressions.Match m = r.Match(queryString);
    
    return m.Success ? System.Uri.UnescapeDataString(m.Groups[1].Value).Replace('+', ' ') : "";
}

protected override void OnLoad(EventArgs e)
{
    string domain = "YOUR_AUTH0_DOMAIN";
    string clientId = "YOUR_CLIENT_ID";
    
    // "externalUrl" below is where we will ask Auth0 to send the authentication response.
    // By default, we calculate the "Authority" (scheme + domain, e.g. "https://somedomain.com") 
    // from the request URL, as seen by SharePoint.
    //
    // If your SharePoint site is behind a load balancer or other setup such that
    // the user sees a different URL than the internal URL for the Sharepoint server, 
    // replace the "externalUrl" logic assignment below with a hardcoded address pointing
    // to the externally visible URL. It should be just the protocol and domain, without
    // a slash at the end. E.g. the end result should look like this:
    // string externalUrl = "https://mysharepointsite.com"
    string externalUrl = HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Authority);
    
    string redirectUri = HttpUtility.UrlEncode(externalUrl + "/_trust/");
    
    string state = GetParameterByName(HttpContext.Current.Request.Url.Query, "Source");

    Response.Redirect("https://" + domain + "/wsfed/" + clientId + "?wreply=" + redirectUri + "&wctx=" + state, true);
}
</script>
