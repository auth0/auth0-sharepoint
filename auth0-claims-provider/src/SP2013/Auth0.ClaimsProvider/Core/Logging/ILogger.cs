using System;

using Microsoft.SharePoint.Administration.Claims;
using System.Collections.Generic;
using Microsoft.SharePoint.WebControls;

namespace Auth0.ClaimsProvider.Core.Logging
{
    public interface ILogger
    {
        void FillResolve(Uri context, SPClaim resolveInput);

        void FillResolve(Uri context, string resolveInput);

        void FillResolveNotInContext(Uri context);

        void FillResolveIssuerMismatch(string originalIssuer, string associatedIssuer);

        void ConnectionsLoaded(int connectionCount);

        void ConnectionsError(Exception ex);

        void CreateUniqueResult(string email, string connection);

        void GetTrustedLoginProvider(Uri context);

        void FillSearch(Uri context, string searchPattern);

        void FillSearchEmpty();

        void FillSearchEmail(string email, string nodeId);

        void FillSearchResults(int totalResults);

        void ResolveInputBulk(string input, string selectedNode);

        void ResolveInputBulkSearching();

        void ResolveInputBulkComplete(int totalUsers);

        void ResolveInputBulkError(Exception error);

        void Resolved(IEnumerable<PickerEntity> entities);

        void ConfigurationInvalid();

        void ConfigurationError(Exception ex);

        void ConfigurationInitialized(Uri context, string domain, string clientId);

        void SearchClientId(Uri context);

        void ClientIdFound(Uri context, string result);
    }
}
