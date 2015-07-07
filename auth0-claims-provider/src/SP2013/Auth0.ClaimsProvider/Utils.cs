namespace Auth0.ClaimsProvider
{
    using System.Linq;
    using System.Text.RegularExpressions;
    using System.Threading;
    using Microsoft.IdentityModel.Claims;
    using Microsoft.SharePoint.Administration;
    using Microsoft.SharePoint.Administration.Claims;
    using System.Collections.Generic;
    using System;
    using Auth0.ClaimsProvider.Core.Logging;

    public static class Utils
    {
        /// <summary>
        /// Get the first TrustedLoginProvider associated with current claim provider
        /// </summary>
        /// <param name="ProviderInternalName"></param>
        /// <returns></returns>
        public static SPTrustedLoginProvider GetSPTrustedLoginProviderForClaimsProvider(string providerInternalName)
        {
            var providers = SPSecurityTokenServiceManager.Local.TrustedLoginProviders.Where(p => p.ClaimProviderName == providerInternalName);

            if (providers != null && providers.Count() > 0)
            {
                if (providers.Count() == 1)
                {
                    return providers.First();
                }
                else
                {
                    UlsLogger.WriteError("Claim provider '{0}' is associated to several TrustedLoginProvider, which is not supported because there is no way to determine what TrustedLoginProvider is currently calling the claim provider during search and resolution.", providerInternalName);
                }
            }

            UlsLogger.WriteError("Claim provider '{0}' is not associated with any SPTrustedLoginProvider, and it cannot create permissions for a trust if it is not associated to it.\r\nUse PowerShell cmdlet Get-SPTrustedIdentityTokenIssuer to create association", providerInternalName);

            return null;
        }

        public static string GetClaimsValue(string claimType)
        {
            var claimsIdentity = Thread.CurrentPrincipal.Identity as ClaimsIdentity;
            return claimsIdentity != null && claimsIdentity.IsAuthenticated && claimsIdentity.Claims.Any(c => c.ClaimType == claimType) ?
                claimsIdentity.Claims.First(c => c.ClaimType == claimType).Value :
                string.Empty;
        }

        public static object GetPropValue(object src, string propName)
        {
            return src.GetType().GetProperty(propName) != null ?
                src.GetType().GetProperty(propName).GetValue(src, null) :
                string.Empty;
        }

        internal static bool ValidEmail(string email)
        {
            var pattern = @"^(?!\.)(""([^""\r\\]|\\[""\r\\])*""|" +
                          @"([-a-z0-9!#$%&'*+/=?^_`{|}~]|(?<!\.)\.)*)(?<!\.)" +
                          @"@[a-z0-9][\w\.-]*[a-z0-9]\.[a-z][a-z\.]*[a-z]$";

            var regex = new Regex(pattern, RegexOptions.IgnoreCase);
            return regex.IsMatch(email);
        }
        public static string UniqueEmail(this User user)
        {
            return user.Email != null ? user.Email : user.UserId.Split('|')[1];
        }

        public static IEnumerable<TSource> DistinctBy<TSource, TKey>(this IEnumerable<TSource> source, Func<TSource, TKey> keySelector)
        {
            if (source == null)
            {
                throw new ArgumentNullException("source");
            }

            if (keySelector == null)
            {
                throw new ArgumentNullException("keySelector");
            }

            var knownKeys = new HashSet<TKey>();
            foreach (var element in source)
            {
                if (knownKeys.Add(keySelector(element)))
                {
                    yield return element;
                }
            }
        }
    }
}