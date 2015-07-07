namespace Auth0.ClaimsProvider
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;
    using System.Net;

    using Microsoft.SharePoint;
    using Microsoft.SharePoint.Administration;
    using Microsoft.SharePoint.Administration.Claims;
    using Microsoft.SharePoint.WebControls;

    using Auth0.ClaimsProvider.Core;
    using Auth0.ClaimsProvider.Core.Model;
    using Auth0.ClaimsProvider.Core.Logging;
    using Auth0.ClaimsProvider.Configuration;

    public class CustomClaimsProvider : SPClaimProvider
    {
        public const char IdentifierValuesSeparator = '|';
        private const string SocialHierarchyNode = "Social";
        private const string EnterpriseHierarchyNode = "Enterprise";
        private const string UsersNode = "Users";
        private const string GroupsNode = "Groups";

        private readonly ILogger logger;
        private readonly IConfigurationRepository configurationRepository;

        private SPTrustedLoginProvider associatedLoginProvider; // Name of the SPTrustedLoginProvider associated with the claim provider
        private Auth0.Client client;
        private Uri clientContext;
        private Auth0Config configuration;

        private bool alwaysResolveValue;
        private string pickerEntityGroupName;
        private string identifierClaimType;

        public override string Name
        {
            get { return ProviderInternalName; }
        }

        public override bool SupportsEntityInformation
        {
            get { return false; }
        }

        public override bool SupportsHierarchy
        {
            get { return true; }
        }

        public override bool SupportsResolve
        {
            get { return true; }
        }

        public override bool SupportsSearch
        {
            get { return true; }
        }

        internal static string ProviderDisplayName
        {
            get { return "Federated Users (Auth0)"; }
        }

        internal static string ProviderInternalName
        {
            get { return "Auth0FederatedUsers"; }
        }

        public CustomClaimsProvider(string displayName)
            : this(displayName, new ConfigurationRepository(), ClaimsProviderEventSource.Log)
        {
        }

        public CustomClaimsProvider(string displayName, IConfigurationRepository configurationRepository, ILogger logger)
            : base(displayName)
        {
            this.logger = logger;
            this.configurationRepository = configurationRepository;

            // TODO: remove this
            ServicePointManager.ServerCertificateValidationCallback += delegate { return true; };
        }

        /// <summary>
        /// Get the client id from the web application.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private string GetWebApplicationClientId(Uri context)
        {
            try
            {
                logger.SearchClientId(context);

                var webApplication = SPWebApplication.Lookup(context);

                // Loop each realm.
                var provider = SPSecurityTokenServiceManager.Local.TrustedLoginProviders.FirstOrDefault(p => p.Name == "Auth0");
                foreach (var realm in provider.ProviderRealms)
                {
                    var realmWebApplication = SPWebApplication.Lookup(realm.Key);
                    if (webApplication.Id == realmWebApplication.Id)
                    {
                        return realm.Value.Replace("urn:", "");
                    }
                }

                // Nothing found.
                return null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        protected void InitializeApiClient(Uri context)
        {
            // Already initialized.
            if (this.client != null && this.clientContext == context)
            {
                return;
            }

            // Invalid.
            this.configuration = this.configurationRepository.GetConfiguration();
            if (!this.configuration.IsValid)
            {
                logger.ConfigurationInvalid();
                return;
            }

            try
            {
                // Split multiple values if any.
                var domains = this.configuration.Domain.Split(new string[] { Environment.NewLine, ";", "," }, StringSplitOptions.None);
                var clientsIds = this.configuration.ClientId.Split(new string[] { Environment.NewLine, ";", "," }, StringSplitOptions.None);
                var clientsSecrets = this.configuration.ClientSecret.Split(new string[] { Environment.NewLine, ";", "," }, StringSplitOptions.None);

                // Try to find the current client.
                var clientIdIndex = Array.IndexOf(clientsIds, Utils.GetClaimsValue(DefaultClaimTypes.ClientId));
                if (clientIdIndex == -1)
                {
                    var webApplicationClientId = GetWebApplicationClientId(context);
                    if (webApplicationClientId != null)
                    {
                        clientIdIndex = Array.IndexOf(clientsIds, webApplicationClientId);
                    }

                    logger.ClientIdFound(context, webApplicationClientId);

                    if (clientIdIndex == -1)
                    {
                        throw new InvalidOperationException("Unable to find client ID for: " + context.ToString());
                    }
                }

                // Get values.
                var clientId = clientsIds[clientIdIndex];
                var domain = domains[clientIdIndex];

                // Initialize client.
                this.client = new Auth0.Client(
                    clientId,
                    clientsSecrets[clientIdIndex],
                    domain, diagnostics: DiagnosticsHeader.Default
                        .AddEnvironment("SharePoint", "2013")
                        .AddEnvironment("ClaimsProvider", GetType().Assembly.FullName));
                this.clientContext = context;

                // Log complete.
                logger.ConfigurationInitialized(context, domain, clientId);
            }
            catch (Exception ex)
            {
                logger.ConfigurationError(ex);
                throw;
            }

            this.alwaysResolveValue = true; //this.auth0Config.AlwaysResolveUserInput;
            this.pickerEntityGroupName = this.configuration.PickerEntityGroupName;
        }

        /// <summary>
        /// List all supported claim types.
        /// </summary>
        /// <param name="claimTypes"></param>
        protected override void FillClaimTypes(List<string> claimTypes)
        {
            if (claimTypes == null)
                throw new ArgumentNullException("claimTypes");

            if (!string.IsNullOrEmpty(this.identifierClaimType))
                claimTypes.Add(this.identifierClaimType);

            claimTypes.Add(DefaultClaimTypes.Connection);
        }

        /// <summary>
        /// List all used claim type values.
        /// </summary>
        /// <param name="claimValueTypes"></param>
        protected override void FillClaimValueTypes(List<string> claimValueTypes)
        {
            if (claimValueTypes == null)
                throw new ArgumentNullException("claimValueTypes");

            claimValueTypes.Add(Microsoft.IdentityModel.Claims.ClaimValueTypes.String);
        }

        /// <summary>
        /// Not implemented.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="entity"></param>
        /// <param name="claims"></param>
        protected override void FillClaimsForEntity(Uri context, SPClaim entity, List<SPClaim> claims)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Only users are supported.
        /// </summary>
        /// <param name="entityTypes"></param>
        protected override void FillEntityTypes(List<string> entityTypes)
        {
            entityTypes.Add(SPClaimEntityTypes.User);
        }

        protected override void FillHierarchy(Uri context, string[] entityTypes, string hierarchyNodeID, int numberOfLevels, SPProviderHierarchyTree hierarchy)
        {
            if (!this.SetLoginProviderForCurrentContext(context))
            {
                return;
            }

            hierarchy.AddChild(new
                    Microsoft.SharePoint.WebControls.SPProviderHierarchyNode(ProviderInternalName, UsersNode, UsersNode, true));
        }

        protected override void FillResolve(Uri context, string[] entityTypes, SPClaim resolveInput, List<PickerEntity> resolved)
        {
            logger.FillResolve(context, resolveInput);

            // Not in context.
            if (!this.SetLoginProviderForCurrentContext(context))
            {
                logger.FillResolveNotInContext(context);
                return;
            }

            // Issuer mismatch.
            if (!String.Equals(resolveInput.OriginalIssuer, SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, this.associatedLoginProvider.Name), StringComparison.OrdinalIgnoreCase))
            {
                logger.FillResolveIssuerMismatch(resolveInput.OriginalIssuer, SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, this.associatedLoginProvider.Name));
                return;
            }

            SPSecurity.RunWithElevatedPrivileges(delegate
            {
                this.InitializeApiClient(context);

                var input = resolveInput.Value.Contains(IdentifierValuesSeparator) ? resolveInput.Value.Split(IdentifierValuesSeparator)[1] : resolveInput.Value;
                var connectionName = resolveInput.Value.Contains(IdentifierValuesSeparator) ? resolveInput.Value.Split(IdentifierValuesSeparator)[0] : string.Empty;

                var consolidatedResults = this.ResolveInputBulk(input, connectionName);
                if (consolidatedResults != null && consolidatedResults.Count > 0)
                {
                    resolved.Add(consolidatedResults.ElementAt(0).PickerEntity);
                    return;
                }

                if (resolveInput.ClaimType == DefaultClaimTypes.Connection)
                {
                    var user = new Auth0.User
                    {
                        Identities = new List<Identity> 
                        { 
                            new Identity { Connection = resolveInput.Value } 
                        }
                    };
                    resolved.Add(this.GetPickerEntity(user, SPClaimEntityTypes.FormsRole));
                }
                else if (resolveInput.ClaimType == DefaultClaimTypes.Role)
                {
                    resolved.Add(this.GetRolePickerEntity(resolveInput.Value));
                }
                else if (this.alwaysResolveValue)
                {
                    var user = new Auth0.User
                    {
                        Email = input,
                        Name = string.Empty,
                        Picture = string.Empty,
                        Identities = new List<Identity> 
                        { 
                            new Identity { Connection = connectionName } 
                        }
                    };

                    resolved.Add(this.GetPickerEntity(user, SPClaimEntityTypes.User));
                }

                logger.Resolved(resolved);
            });
        }

        protected override void FillResolve(Uri context, string[] entityTypes, string resolveInput, List<PickerEntity> resolved)
        {
            logger.FillResolve(context, resolveInput);

            // Not in context.
            if (!this.SetLoginProviderForCurrentContext(context))
            {
                logger.FillResolveNotInContext(context);
                return;
            }

            SPSecurity.RunWithElevatedPrivileges(delegate
            {
                this.InitializeApiClient(context);

                var consolidatedResults = this.ResolveInputBulk(resolveInput, string.Empty);
                if (consolidatedResults != null)
                {
                    foreach (var result in consolidatedResults)
                    {
                        resolved.Add(result.PickerEntity);
                    }
                }
            });
        }

        protected override void FillSchema(SPProviderSchema schema)
        {

        }

        /// <summary>
        /// /Search for a value.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="entityTypes"></param>
        /// <param name="searchPattern"></param>
        /// <param name="hierarchyNodeID"></param>
        /// <param name="maxCount"></param>
        /// <param name="searchTree"></param>
        protected override void FillSearch(Uri context, string[] entityTypes, string searchPattern, string hierarchyNodeID, int maxCount, SPProviderHierarchyTree searchTree)
        {
            logger.FillSearch(context, searchPattern);

            if (!this.SetLoginProviderForCurrentContext(context))
            {
                return;
            }

            SPProviderHierarchyNode matchNode = null;
            SPSecurity.RunWithElevatedPrivileges(delegate
            {
                this.InitializeApiClient(context);

                var consolidatedResults = this.ResolveInputBulk(searchPattern, hierarchyNodeID);
                if (consolidatedResults != null)
                {
                    // All users from connections.
                    if (string.IsNullOrEmpty(searchPattern))
                    {
                        logger.FillSearchEmpty();

                        this.CreatePeoplePickerConnectionNodes(hierarchyNodeID)
                            .ToList()
                            .ForEach(r => consolidatedResults.Add(r));
                    }
                    // Specific email from specific connection
                    else if (this.alwaysResolveValue &&
                             Utils.ValidEmail(searchPattern) &&
                             !consolidatedResults.Any(r => r.User.Email.Equals(searchPattern, StringComparison.OrdinalIgnoreCase) && r.Attribute.PeoplePickerAttributeHierarchyNodeId == hierarchyNodeID))
                    {
                        logger.FillSearchEmail(searchPattern, hierarchyNodeID);

                        var result = this.CreateUniqueResult(searchPattern, UsersNode);
                        consolidatedResults.Add(result);
                    }

                    if (consolidatedResults.Count > 0)
                    {
                        logger.FillSearchResults(consolidatedResults.Count);

                        foreach (var consolidatedResult in consolidatedResults)
                        {
                            // Add current PickerEntity to the corresponding attribute in the hierarchy
                            if (!searchTree.HasChild(UsersNode))
                            {
                                matchNode = new SPProviderHierarchyNode(
                                    ProviderInternalName,
                                    consolidatedResult.Attribute.PeoplePickerAttributeDisplayName,
                                    consolidatedResult.Attribute.PeoplePickerAttributeHierarchyNodeId,
                                    true);
                                searchTree.AddChild(matchNode);
                            }

                            matchNode.AddEntity(consolidatedResult.PickerEntity);
                        }

                        return;
                    }
                }
            });
        }
        protected virtual ICollection<ConsolidatedResult> ResolveInputBulk(string input, string selectedNode)
        {
            logger.ResolveInputBulk(input, selectedNode);

            // Stop if no input is available.
            if (string.IsNullOrEmpty(input))
            {
                return null;
            }

            // Initialize the client if required.
            if (this.client == null)
            {
                return null;
            }

            IEnumerable<Auth0.User> users = null;

            try
            {
                logger.ResolveInputBulkSearching();

                // Search for users.
                var socialUsers = this.client.GetSocialUsers(input);
                var enterpriseUsers = this.client.GetEnterpriseUsers(input);

                // Distinct by user.Email
                users = socialUsers.Union(enterpriseUsers).DistinctBy(u => u.Email);

                // Log results.
                logger.ResolveInputBulkComplete(users != null ? users.Count() : 0);
            }
            catch (Exception ex)
            {
                logger.ResolveInputBulkError(ex);
            }

            var consolidatedResults = new Collection<ConsolidatedResult>();

            // Add all users as consolidated results.
            if (users != null)
            {
                foreach (var user in users)
                {
                    consolidatedResults.Add(new ConsolidatedResult
                    {
                        Attribute = new ClaimAttribute
                        {
                            ClaimEntityType = SPClaimEntityTypes.User,
                            PeoplePickerAttributeDisplayName = UsersNode,
                            PeoplePickerAttributeHierarchyNodeId = UsersNode
                        },
                        User = user,
                        PickerEntity = this.GetPickerEntity(user, SPClaimEntityTypes.User)
                    });
                }
            }

            return consolidatedResults;
        }

        /// <summary>
        /// Create picker entity for a role.
        /// </summary>
        /// <param name="role"></param>
        /// <returns></returns>
        protected virtual PickerEntity GetRolePickerEntity(string role)
        {
            var pickerEntity = CreatePickerEntity();
            pickerEntity.DisplayText = string.Format("'{0}' Role", role);
            pickerEntity.Description = string.Format("[{0}] '{1}' Role", ProviderInternalName, role);
            pickerEntity.EntityType = SPClaimEntityTypes.FormsRole;
            pickerEntity.Claim = new SPClaim(DefaultClaimTypes.Role, role, Microsoft.IdentityModel.Claims.ClaimValueTypes.String,
                    SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, this.associatedLoginProvider.Name));
            pickerEntity.IsResolved = true;
            pickerEntity.EntityGroupName = this.pickerEntityGroupName;
            return pickerEntity;
        }

        /// <summary>
        /// Create a picker entity for a user.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="claimEntityType"></param>
        /// <returns></returns>
        protected virtual PickerEntity GetPickerEntity(Auth0.User user, string claimEntityType)
        {
            var pickerEntity = CreatePickerEntity();
            SPClaim claim = null;

            if (claimEntityType == SPClaimEntityTypes.User)
            {
                claim = new SPClaim(this.identifierClaimType,
                    string.IsNullOrEmpty(this.configuration.IdentifierUserField) || this.configuration.IdentifierUserField == "Email" ? user.UniqueEmail() :
                        Utils.GetPropValue(user, this.configuration.IdentifierUserField).ToString(),
                    Microsoft.IdentityModel.Claims.ClaimValueTypes.String,
                    SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, this.associatedLoginProvider.Name));

                var displayText = !string.IsNullOrEmpty(user.FamilyName) && !string.IsNullOrEmpty(user.GivenName) ?
                    string.Format("{0} {1}", user.GivenName, user.FamilyName) : user.Name;

                pickerEntity.DisplayText = !string.IsNullOrEmpty(displayText) ? string.Format("{0} ({1})", displayText, user.Email) : user.Email;
                pickerEntity.Description = string.Format("Email: {0}; Name: {1}", user.Email, user.Name);
                pickerEntity.EntityType = SPClaimEntityTypes.User;
                pickerEntity.EntityData[PeopleEditorEntityDataKeys.DisplayName] = displayText;
                pickerEntity.EntityData[PeopleEditorEntityDataKeys.Email] = user.Email;
                pickerEntity.EntityData["Picture"] = user.Picture;
            }
            else if (claimEntityType == SPClaimEntityTypes.FormsRole)
            {
                claim = new SPClaim(DefaultClaimTypes.Connection,
                    user.Identities.First().Connection,
                    Microsoft.IdentityModel.Claims.ClaimValueTypes.String,
                    SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, this.associatedLoginProvider.Name));
                pickerEntity.DisplayText = string.Format( "All Users ({0})", user.Identities.First().Connection);
                pickerEntity.Description = string.Format("[{0}] All Users from '{1}'",
                    ProviderInternalName, user.Identities.First().Connection);
                pickerEntity.EntityType = SPClaimEntityTypes.FormsRole;
            }

            pickerEntity.Claim = claim;
            pickerEntity.IsResolved = true;
            pickerEntity.EntityGroupName = this.pickerEntityGroupName;
            return pickerEntity;
        }

        /// <summary>
        /// Get SP Trusted Login Provider.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        protected virtual bool SetLoginProviderForCurrentContext(Uri context)
        {
            var webApplication = SPWebApplication.Lookup(context);
            if (webApplication == null)
            {
                return false;
            }

            SPSite site = null;
            try
            {
                site = new SPSite(context.AbsoluteUri);
            }
            catch (Exception)
            {
                this.associatedLoginProvider = Utils.GetSPTrustedLoginProviderForClaimsProvider(ProviderInternalName);
                if (this.associatedLoginProvider != null && this.associatedLoginProvider.IdentityClaimTypeInformation != null)
                {
                    this.identifierClaimType = this.associatedLoginProvider.IdentityClaimTypeInformation.InputClaimType;
                }

                return this.associatedLoginProvider != null;
            }

            if (site == null)
            {
                return false;
            }

            using (site)
            {
                var iisSettings = webApplication.GetIisSettingsWithFallback(site.Zone);
                if (!iisSettings.UseTrustedClaimsAuthenticationProvider)
                {
                    return false;
                }

                // Figure out if we have a trusted login provider.
                foreach (var provider in iisSettings.ClaimsAuthenticationProviders)
                {
                    if (provider.GetType() == typeof(Microsoft.SharePoint.Administration.SPTrustedAuthenticationProvider))
                    {
                        if (provider.ClaimProviderName == ProviderInternalName)
                        {
                            this.associatedLoginProvider = Utils.GetSPTrustedLoginProviderForClaimsProvider(ProviderInternalName);
                            if (this.associatedLoginProvider != null && this.associatedLoginProvider.IdentityClaimTypeInformation != null)
                            {
                                this.identifierClaimType = this.associatedLoginProvider.IdentityClaimTypeInformation.InputClaimType;
                            }

                            return this.associatedLoginProvider != null;
                        }
                    }
                }

                return false;
            }
        }

        private static SPProviderHierarchyNode GetParentNode(string nodeName)
        {
            return new SPProviderHierarchyNode(ProviderInternalName, nodeName, nodeName.ToLowerInvariant(), false);
        }

        /// <summary>
        /// Create a unique result for an email in a connection.
        /// </summary>
        /// <param name="email"></param>
        /// <param name="connectionName"></param>
        /// <returns></returns>
        private ConsolidatedResult CreateUniqueResult(string email, string connectionName)
        {
            logger.CreateUniqueResult(email, connectionName);

            var user = new Auth0.User
            {
                Email = email,
                Name = string.Empty,
                Picture = string.Empty,
                Identities = new List<Identity> 
                { 
                    new Identity 
                    { 
                        Connection = connectionName, 
                        IsSocial = this.IsSocialConnection(connectionName)
                    }
                }
            };

            return new ConsolidatedResult
            {
                Attribute = new ClaimAttribute
                {
                    ClaimEntityType = SPClaimEntityTypes.User,
                    PeoplePickerAttributeDisplayName = connectionName,
                    PeoplePickerAttributeHierarchyNodeId = connectionName
                },
                User = user,
                PickerEntity = this.GetPickerEntity(user, SPClaimEntityTypes.User)
            };
        }

        /// <summary>
        /// Greate the nodes in the People Picker representing all connections.
        /// </summary>
        /// <param name="selectedNode"></param>
        /// <returns></returns>
        private IEnumerable<ConsolidatedResult> CreatePeoplePickerConnectionNodes(string selectedNode)
        {
            var identities = new List<Identity>();

            // Get a list of all connections.
            var connections = this.GetConnections(selectedNode);
            foreach (var connection in connections)
            {
                identities.Add(new Identity
                {
                    Connection = connection.Name,
                    IsSocial = this.IsSocialConnection(connection.Name)
                });
            }

            // Add all connections as identities.
            var results = new List<ConsolidatedResult>();
            foreach (var identity in identities)
            {
                var user = new Auth0.User
                {
                    Identities = new List<Identity> { identity }
                };

                results.Add(new ConsolidatedResult
                {
                    Attribute = new ClaimAttribute
                    {
                        ClaimEntityType = SPClaimEntityTypes.FormsRole,
                        PeoplePickerAttributeDisplayName = identity.Connection,
                        PeoplePickerAttributeHierarchyNodeId = identity.Connection
                    },
                    User = user,
                    PickerEntity = this.GetPickerEntity(user, SPClaimEntityTypes.FormsRole)
                });
            }

            return results;
        }

        /// <summary>
        /// Get all connections from Auth0.
        /// </summary>
        /// <returns></returns>
        private IEnumerable<Auth0.Connection> GetConnections()
        {
            return this.GetConnections(string.Empty);
        }

        /// <summary>
        /// Get connections for a specific type.
        /// </summary>
        /// <param name="connectionType"></param>
        /// <returns></returns>
        private IEnumerable<Auth0.Connection> GetConnections(string connectionType)
        {
            IEnumerable<Auth0.Connection> connections = null;

            try
            {
                if (string.IsNullOrEmpty(connectionType))
                {
                    connections = this.client.GetConnections();
                }
                else if (connectionType.Equals(EnterpriseHierarchyNode, StringComparison.OrdinalIgnoreCase))
                {
                    connections = this.client.GetEnterpriseConnections();
                }
                else if (connectionType.Equals(SocialHierarchyNode, StringComparison.OrdinalIgnoreCase))
                {
                    connections = this.client.GetSocialConnections();
                }

                logger.ConnectionsLoaded(connections != null ? connections.Count() : 0);
            }
            catch (Exception ex)
            {
                logger.ConnectionsError(ex);
            }

            return connections != null ? connections : new List<Auth0.Connection>();
        }

        /// <summary>
        /// Is the current connection a social connection.
        /// </summary>
        /// <param name="connectionName"></param>
        /// <returns></returns>
        private bool IsSocialConnection(string connectionName)
        {
            return this.GetConnections(SocialHierarchyNode).Any(c => c.Name.Equals(connectionName, StringComparison.OrdinalIgnoreCase));
        }
    }
}