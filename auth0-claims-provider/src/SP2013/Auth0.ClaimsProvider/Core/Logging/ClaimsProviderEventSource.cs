using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;

namespace Auth0.ClaimsProvider.Core.Logging
{
    [EventSource(Name = "Auth0-ClaimsProviderEventSource")]
    public class ClaimsProviderEventSource : EventSource, ILogger
    {
        public static ClaimsProviderEventSource Log = new ClaimsProviderEventSource();

        [NonEvent]
        public void FillResolve(Uri context, Microsoft.SharePoint.Administration.Claims.SPClaim resolveInput)
        {
            if (IsEnabled())
            {
                FillResolve("SPClaim", context.ToString(), resolveInput != null ? resolveInput.ClaimType + ":" + resolveInput.Value : "");
            }
        }

        [NonEvent]
        public void FillResolve(Uri context, string resolveInput)
        {
            if (IsEnabled())
            {
                FillResolve("string", context.ToString(), resolveInput);
            }
        }

        [Event(1, Message = "FillResolve {0}: {1}. [ResolveInput:'{2}']", Level = EventLevel.Verbose)]
        public void FillResolve(string type, string context, string resolveInput)
        {
            WriteEvent(1, type, context, resolveInput);
        }

        [NonEvent]
        public void FillResolveNotInContext(Uri context)
        {
            if (IsEnabled())
            {
                FillResolveNotInContext(context.ToString());
            }
        }

        [Event(2, Message = "FillResolve: Not In Context - {0}", Level = EventLevel.Verbose)]
        public void FillResolveNotInContext(string context)
        {
            WriteEvent(2, context);
        }

        [Event(3, Message = "FillResolve: Issuer Mismatch [Original:{0} - Associated:{1}]", Level = EventLevel.Verbose)]
        public void FillResolveIssuerMismatch(string originalIssuer, string associatedIssuer)
        {
            WriteEvent(3, originalIssuer, associatedIssuer);
        }

        [Event(4, Message = "Connections Loaded: {0}", Level = EventLevel.Verbose)]
        public void ConnectionsLoaded(int connectionsCount)
        {
            WriteEvent(4, connectionsCount);
        }

        [NonEvent]
        public void ConnectionsError(Exception ex)
        {
            if (IsEnabled())
            {
                ConnectionsError(ex.Message, ex.ToString());
            }
        }

        [Event(5, Message = "Error Loading Connections: {0}", Level = EventLevel.Error)]
        public void ConnectionsError(string errorMessage, string strackTrace)
        {
            WriteEvent(5, errorMessage, strackTrace);
        }

        [Event(6, Message = "Create Unique Result: User='{0}' - Connection='{1}'", Level = EventLevel.Verbose)]
        public void CreateUniqueResult(string email, string connection)
        {
            WriteEvent(6, email, connection);
        }

        [NonEvent]
        public void GetTrustedLoginProvider(Uri context)
        {
            if (IsEnabled())
            {
                GetTrustedLoginProvider(context.ToString());
            }
        }

        [Event(7, Message = "Get Trusted Login Provider: {0}", Level = EventLevel.Verbose)]
        public void GetTrustedLoginProvider(string context)
        {
            WriteEvent(7, context);
        }

        [NonEvent]
        public void FillSearch(Uri context, string searchPattern)
        {
            if (IsEnabled())
            {
                FillSearch(context.ToString(), searchPattern);
            }
        }

        [Event(8, Message = "Fill Search: {0} (pattern='{1}')", Level = EventLevel.Verbose)]
        public void FillSearch(string context, string searchPattern)
        {
            WriteEvent(8, context, searchPattern);
        }

        [Event(9, Message = "Fill Search: Empty", Level = EventLevel.Verbose)]
        public void FillSearchEmpty()
        {
            WriteEvent(9);
        }

        [Event(10, Message = "Fill Search Email: {0} (Node: {1})", Level = EventLevel.Verbose)]
        public void FillSearchEmail(string email, string nodeId)
        {
            WriteEvent(10, email, nodeId);
        }

        [Event(11, Message = "Fill Search Complete: {0} results.", Level = EventLevel.Verbose)]
        public void FillSearchResults(int totalResults)
        {
            WriteEvent(11, totalResults);
        }

        [Event(12, Message = "Resolve Input Bulk: '{0}' (node='{1}').", Level = EventLevel.Verbose)]
        public void ResolveInputBulk(string input, string selectedNode)
        {
            WriteEvent(12, input, selectedNode);
        }

        [Event(13, Message = "Resolve Input Bulk: Searching...", Level = EventLevel.Verbose)]
        public void ResolveInputBulkSearching()
        {
            WriteEvent(13);
        }

        [Event(14, Message = "Resolve Input Bulk: Found {0}", Level = EventLevel.Verbose)]
        public void ResolveInputBulkComplete(int totalUsers)
        {
            WriteEvent(14, totalUsers);
        }

        [NonEvent]
        public void ResolveInputBulkError(Exception ex)
        {
            if (IsEnabled())
            {
                ConnectionsError(ex.Message, ex.ToString());
            }
        }

        [Event(15, Message = "Resolve Input Bulk Error: {0}", Level = EventLevel.Error)]
        public void ResolveInputBulkError(string errorMessage, string strackTrace)
        {
            WriteEvent(15, errorMessage, strackTrace);
        }

        [NonEvent]
        public void Resolved(IEnumerable<Microsoft.SharePoint.WebControls.PickerEntity> entities)
        {
            if (IsEnabled())
            {
                foreach (var e in entities)
                {
                    ResolvedEntity(e.Description);
                }
            }
        }

        [Event(16, Message = "Resolved Entity: {0}", Level = EventLevel.Verbose)]
        public void ResolvedEntity(string description)
        {
            WriteEvent(16, description);
        }

        [Event(17, Message = "Invalid Configuration", Level = EventLevel.Warning)]
        public void ConfigurationInvalid()
        {
            WriteEvent(17);
        }

        [NonEvent]
        public void ConfigurationError(Exception ex)
        {
            if (IsEnabled())
            {
                ConfigurationError(ex.Message, ex.ToString());
            }
        }

        [Event(18, Message = "Configuration Error: {0}", Level = EventLevel.Error)]
        public void ConfigurationError(string errorMessage, string strackTrace)
        {
            WriteEvent(18, errorMessage, strackTrace);
        }

        [NonEvent]
        public void ConfigurationInitialized(Uri context, string domain, string clientId)
        {
            if (IsEnabled())
            {
                ConfigurationInitialized(context.ToString(), domain, clientId);
            }
        }

        [Event(19, Message = "Configuration Initialized for {0}: {1}, {2}", Level = EventLevel.Informational)]
        public void ConfigurationInitialized(string context, string domain, string clientId)
        {
            WriteEvent(19, context, domain, clientId);
        }

        [NonEvent]
        public void SearchClientId(Uri context)
        {
            if (IsEnabled())
            {
                SearchClientId(context.ToString());
            }
        }

        [Event(20, Message = "Searching Client Id for: {0}", Level = EventLevel.Informational)]
        public void SearchClientId(string context)
        {
            WriteEvent(20, context);
        }

        [NonEvent]
        public void ClientIdFound(Uri context, string result)
        {
            if (IsEnabled())
            {
                ClientIdFound(context.ToString(), result);
            }
        }

        [Event(21, Message = "Client Id for {0}: '{1}'", Level = EventLevel.Informational)]
        public void ClientIdFound(string context, string result)
        {
            WriteEvent(21, context, result);
        }

        [Event(22, Message = "SetLoginProviderForCurrentContext for {0} failed: '{1}'", Level = EventLevel.Warning)]
        public void SetLoginProviderForCurrentContextFailed(string uri, string reason)
        {
            WriteEvent(22, uri, reason);
        }
    }
}
