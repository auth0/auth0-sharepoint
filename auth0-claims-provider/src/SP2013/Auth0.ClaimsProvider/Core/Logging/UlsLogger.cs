using Microsoft.SharePoint.Administration;

using System;
using System.Linq;
using System.Text;
using System.Collections.Generic;

namespace Auth0.ClaimsProvider.Core.Logging
{
    public class UlsLogger : SPDiagnosticsServiceBase
    {
        public static string AreaName = "Auth0";

        private static UlsLogger _instance;

        private static readonly object _syncLock = new object();

        public static UlsLogger Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_syncLock)
                    {
                        if (_instance == null)
                            _instance = new UlsLogger();
                    }
                }

                return _instance;
            }
        }

        private UlsLogger()
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
                var category = UlsLogger.Instance.Areas[AreaName].Categories["ClaimsProvider"];
                UlsLogger.Instance.WriteTrace(0, category, TraceSeverity.Verbose,
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
                var category = UlsLogger.Instance.Areas[AreaName].Categories["ClaimsProviderErrors"];
                UlsLogger.Instance.WriteTrace(0, category, TraceSeverity.Unexpected,
                    args != null && args.Length > 0 ? String.Format(message, args) : message);
            }
            catch (Exception)
            {

            }
        }
    }
}
