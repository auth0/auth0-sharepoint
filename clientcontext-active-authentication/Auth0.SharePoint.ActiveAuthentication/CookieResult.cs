using System;

namespace Auth0.SharePoint.ActiveAuthentication
{
    internal class CookieResult
    {
        public string FedAuth { get; set; }
        public DateTime Expires { get; set; }
        public Uri Host { get; set; }
    }
}