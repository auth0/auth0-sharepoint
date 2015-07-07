using Microsoft.SharePoint.Administration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Auth0.ClaimsProvider
{
    public class Auth0LoggingService : SPDiagnosticsServiceBase
    {
        public static string AreaName = "Auth0";

        private static Auth0LoggingService _instance;

        private static readonly object _syncLock = new object();

        public static Auth0LoggingService Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_syncLock)
                    {
                        if (_instance == null)
                            _instance = new Auth0LoggingService();
                    }
                }
                return _instance;
            }
        }

        private Auth0LoggingService()
            : base("Auth0 Logging Service", SPFarm.Local)
        {

        }

        protected override IEnumerable<SPDiagnosticsArea> ProvideAreas()
        {
            return new List<SPDiagnosticsArea>
            {
                new SPDiagnosticsArea(AreaName, new List<SPDiagnosticsCategory> 
                {
                    new SPDiagnosticsCategory("ClaimsProvider", TraceSeverity.Verbose, EventSeverity.Verbose),
                    new SPDiagnosticsCategory("ClaimsProviderErrors", TraceSeverity.Unexpected, EventSeverity.Error)
                })
            };
        }

        public static void Write(string message, params object[] args)
        {
            try
            {
                var category = Auth0LoggingService.Instance.Areas[AreaName].Categories["ClaimsProvider"];
                Auth0LoggingService.Instance.WriteTrace(0, category, TraceSeverity.Verbose,
                    args != null && args.Length > 0 ? String.Format(message, args) : message);
            }
            catch (Exception)
            {

            }
        }

        public static void WriteError(string message, params object[] args)
        {
            try
            {
                var category = Auth0LoggingService.Instance.Areas[AreaName].Categories["ClaimsProviderErrors"];
                Auth0LoggingService.Instance.WriteTrace(0, category, TraceSeverity.Unexpected,
                    args != null && args.Length > 0 ? String.Format(message, args) : message);
            }
            catch (Exception)
            {

            }
        }
    }
}
