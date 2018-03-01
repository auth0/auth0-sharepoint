<%@ Page Language="C#"%>
<script runat="server">
protected override void OnLoad(EventArgs e)
{
    string domain = "YOUR_AUTH0_DOMAIN";
    string clientId = "YOUR_CLIENT_ID";
    string redirectUri = HttpUtility.UrlEncode(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Authority) + "/_trust/");

    Response.Redirect("https://" + domain + "/wsfed/" + clientId + "?wreply=" + redirectUri, true);
}
</script>
