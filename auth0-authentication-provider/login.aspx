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
    string redirectUri = HttpUtility.UrlEncode(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Authority) + "/_trust/");
    string state = GetParameterByName(HttpContext.Current.Request.Url.Query, "Source");

    Response.Redirect("https://" + domain + "/wsfed/" + clientId + "?wreply=" + redirectUri + "&wctx=" + state, true);
}
</script>
