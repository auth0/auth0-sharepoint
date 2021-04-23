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
    
    // If your SharePoint site is behind a load balancer or other setup such that
    // the user sees a different URL, replace "externalUrl" with the address that users
    // use in the browser. Don't use a slash at the end. E.g.
    // string externalUrl = "https://mysharepointsite.com"
    string externalUrl = HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Authority);
    
    string redirectUri = HttpUtility.UrlEncode(externalUrl + "/_trust/");
    
    string state = GetParameterByName(HttpContext.Current.Request.Url.Query, "Source");

    Response.Redirect("https://" + domain + "/wsfed/" + clientId + "?wreply=" + redirectUri + "&wctx=" + state, true);
}
</script>
