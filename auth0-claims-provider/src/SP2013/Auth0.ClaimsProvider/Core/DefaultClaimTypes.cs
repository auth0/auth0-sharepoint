using System;

namespace Auth0.ClaimsProvider.Core
{
    public static class DefaultClaimTypes
    {
        public const string ClientId = "http://schemas.auth0.com/clientID";
        
        public const string Connection = "http://schemas.auth0.com/connection";

        public const string Role = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
    }
}
