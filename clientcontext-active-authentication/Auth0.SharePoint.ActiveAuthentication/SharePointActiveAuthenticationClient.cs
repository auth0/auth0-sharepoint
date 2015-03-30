using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IO;
using System.Linq;
using System.Net;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Xml.Linq;

namespace Auth0.SharePoint.ActiveAuthentication
{
    public class SharePointActiveAuthenticationClient
    {
        private const string WsuNamespace =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

        private readonly Uri _callbackUrl;
        private readonly string _password;
        private readonly object _syncRoot = new object();
        private readonly string _username;
        private readonly string _wsTrustUsernameEndpoint;
        private CookieContainer _cachedCookieContainer;
        private DateTime _expires = DateTime.MinValue;

        public Action<string> Logger = s => { };

    /// <summary>
        /// Initialize the client.
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="domain"></param>
        /// <param name="connection"></param>
        /// <param name="callbackUrl"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        public SharePointActiveAuthenticationClient(string clientId, string domain, string connection, Uri callbackUrl,
            string username, string password)
        {
            _wsTrustUsernameEndpoint = String.Format("https://{0}/{1}/trust/usernamemixed?connection={2}", domain,
                clientId, connection);
            _callbackUrl = callbackUrl;
            _username = username;
            _password = password;
        }

        /// <summary>
        /// The cookie container which contains the FedAuth cookie.
        /// </summary>
        public CookieContainer CookieContainer
        {
            get { return GetCookieContainer(); }
        }

        /// <summary>
        /// Get the cached cookie container or create a new one.
        /// </summary>
        /// <returns></returns>
        private CookieContainer GetCookieContainer()
        {
            if (_cachedCookieContainer == null || DateTime.Now > _expires)
            {
                lock (_syncRoot)
                {
                    if (_cachedCookieContainer == null || DateTime.Now > _expires)
                    {
                        var cookies = GetFedAuthCookie();
                        if (cookies != null && !string.IsNullOrEmpty(cookies.FedAuth))
                        {
                            _expires = cookies.Expires;

                            // Create a new cookie container.
                            var cookieContainer = new CookieContainer();
                            cookieContainer.Add(new Cookie("FedAuth", cookies.FedAuth)
                            {
                                Expires = cookies.Expires,
                                Path = "/",
                                Secure = cookies.Host.Scheme == "https",
                                HttpOnly = true,
                                Domain = cookies.Host.Host
                            });

                            // Cache the container.
                            _cachedCookieContainer = cookieContainer;
                            return cookieContainer;
                        }

                        return null;
                    }
                }
            }
            return _cachedCookieContainer;
        }

        private CookieResult GetFedAuthCookie()
        {
            var cookies = new CookieResult();

            try
            {
                var stsResponse = AuthenticateWsTrustUsername();

                // Filter out elements that are not accepted by SharePoint.
                var filteredResponse = "";
                using (var reader = new StringReader(stsResponse))
                {
                    var allowedLine = true;
                    var line = String.Empty;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.Contains("trust:Lifetime") || line.Contains("trust:KeyType"))
                            allowedLine = false;
                        if (allowedLine)
                            filteredResponse += line + "\n";
                        if (line.Contains("/wsp:AppliesTo") || line.Contains("/trust:KeyType"))
                            allowedLine = true;
                    }
                }

                // Find the expiration.
                var document = XDocument.Parse(stsResponse);
                var expires = from result in document.Descendants()
                    where result.Name == XName.Get("Expires", WsuNamespace)
                    select result;
                cookies.Expires = Convert.ToDateTime(expires.First().Value);

                // Open the _trust endpoint.
                var request = CreateSharePointPostRequest(_callbackUrl.ToString());
                using (var stream = request.GetRequestStream())
                {
                    // Post the response.
                    var data = Encoding.UTF8.GetBytes("wa=wsignin1.0&wresult=" + Uri.EscapeDataString(filteredResponse));
                    stream.Write(data, 0, data.Length);
                    stream.Close();

                    // Get the cookie.
                    using (var webResponse = request.GetResponse() as HttpWebResponse)
                    {
                        if (webResponse == null || webResponse.Cookies == null)
                            return null;
                        var fedAuthCookie = webResponse.Cookies["FedAuth"];
                        if (fedAuthCookie == null)
                            return null;
                        cookies.FedAuth = fedAuthCookie.Value;
                        cookies.Host = request.RequestUri;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger(String.Format("Error while getting FedAuth cookie: {0}", ex.Message));
                return null;
            }

            return cookies;
        }

        /// <summary>
        /// Create
        /// </summary>
        /// <param name="url"></param>
        /// <returns></returns>
        private HttpWebRequest CreateSharePointPostRequest(string url)
        {
            var request = WebRequest.Create(url) as HttpWebRequest;
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.CookieContainer = new CookieContainer();
            request.AllowAutoRedirect = false;
            request.UserAgent = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)";
            return request;
        }

        /// <summary>
        /// Active authentication.
        /// </summary>
        /// <returns></returns>
        private string AuthenticateWsTrustUsername()
        {
            var rst = new RequestSecurityToken
            {
                RequestType = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue",
                AppliesTo = new EndpointReference(_callbackUrl.ToString()),
                KeyType = "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey",
                TokenType = "urn:oasis:names:tc:SAML:1.0:assertion"
            };

            var binding = new WSHttpBinding();
            binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
            binding.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.NegotiateServiceCredential = false;
            binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.None;

            using (var trustClient = new WsTrustFeb2005ContractClient(binding, new EndpointAddress(_wsTrustUsernameEndpoint)))
            {
                Logger(String.Format("Authenticating to {0} with {1}.", _wsTrustUsernameEndpoint, _username));

                // Active authentication.
                trustClient.ClientCredentials.UserName.UserName = _username;
                trustClient.ClientCredentials.UserName.Password = _password;
                var response = trustClient.EndIssue(
                    trustClient.BeginIssue(
                        Message.CreateMessage(MessageVersion.Default,
                            "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue",
                            new RequestBodyWriter(new WSTrustFeb2005RequestSerializer(), rst)),
                        null,
                        null));
                trustClient.Close();

                // Return the response.
                using (var reader = response.GetReaderAtBodyContents())
                    return reader.ReadOuterXml();
            }
        }
    }
}