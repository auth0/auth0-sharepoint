namespace Auth0.ClaimsProvider
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;
    using System.Net;
    using Auth0.ClaimsProvider.Configuration;
    using Microsoft.SharePoint;
    using Microsoft.SharePoint.Administration;
    using Microsoft.SharePoint.Administration.Claims;
    using Microsoft.SharePoint.WebControls;

    public class CustomClaimsProvider : SPClaimProvider
    {
        public const string ClientIdClaimsType = "http://schemas.auth0.com/clientID";
        public const string ConnectionClaimType = "http://schemas.auth0.com/connection";
        public const string RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
        public const char IdentifierValuesSeparator = '|';
        private const string SocialHierarchyNode = "Social";
        private const string EnterpriseHierarchyNode = "Enterprise";
        private const string UsersNode = "Users";
        private const string GroupsNode = "Groups";

        private readonly IConfigurationRepository configurationRepository;

        private SPTrustedLoginProvider associatedSPTrustedLoginProvider; // Name of the SPTrustedLoginProvider associated with the claim provider
        private Auth0.Client auth0Client;
        private Auth0Config auth0Config;
        private bool alwaysResolveValue;
        private string pickerEntityGroupName;
        private string identifierClaimType;

        public CustomClaimsProvider(string displayName)
            : this(displayName, new ConfigurationRepository())
        {
        }

        public CustomClaimsProvider(string displayName, IConfigurationRepository configurationRepository)
            : base(displayName)
        {
            this.configurationRepository = configurationRepository;

            // TODO: remove this
            ServicePointManager.ServerCertificateValidationCallback += delegate { return true; };
        }

        public override string Name
        {
            get
            {
                return ProviderInternalName;
            }
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

        protected override void FillClaimTypes(List<string> claimTypes)
        {
            if (claimTypes == null)
            {
                throw new ArgumentNullException("claimTypes");
            }

            if (!string.IsNullOrEmpty(this.identifierClaimType))
            {
                claimTypes.Add(this.identifierClaimType);
            }

            claimTypes.Add(ConnectionClaimType);
        }

        protected override void FillClaimValueTypes(List<string> claimValueTypes)
        {
            if (claimValueTypes == null)
            {
                throw new ArgumentNullException("claimValueTypes");
            }

            claimValueTypes.Add(Microsoft.IdentityModel.Claims.ClaimValueTypes.String);
        }

        protected override void FillClaimsForEntity(Uri context, SPClaim entity, List<SPClaim> claims)
        {
            throw new NotImplementedException();
        }

        protected override void FillEntityTypes(List<string> entityTypes)
        {
            entityTypes.Add(SPClaimEntityTypes.User);
        }

        protected override void FillHierarchy(Uri context, string[] entityTypes, string hierarchyNodeID, int numberOfLevels, SPProviderHierarchyTree hierarchy)
        {
            if (!this.SetSPTrustInCurrentContext(context))
            {
                return;
            }

            hierarchy.AddChild(new
                    Microsoft.SharePoint.WebControls.SPProviderHierarchyNode(
                        ProviderInternalName, UsersNode, UsersNode, true));
        }

        protected override void FillResolve(Uri context, string[] entityTypes, SPClaim resolveInput, List<PickerEntity> resolved)
        {
            Auth0LoggingService.Write("FillResolve input: {0}", resolveInput != null ? resolveInput.ClaimType + "/" + resolveInput.Value : "empty");

            if (!this.SetSPTrustInCurrentContext(context))
            {
                Auth0LoggingService.Write("FillResolve: SetSPTrustInCurrentContext=false.");
                return;
            }

            if (!String.Equals(resolveInput.OriginalIssuer,
                    SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, this.associatedSPTrustedLoginProvider.Name),
                    StringComparison.OrdinalIgnoreCase))
            {
                Auth0LoggingService.Write("FillResolve: Original issuers don't match, {0} != {1}.", resolveInput.OriginalIssuer, SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, this.associatedSPTrustedLoginProvider.Name));
                return;
            }

            SPSecurity.RunWithElevatedPrivileges(delegate
            {
                var input = resolveInput.Value.Contains(IdentifierValuesSeparator) ?
                    resolveInput.Value.Split(IdentifierValuesSeparator)[1] : resolveInput.Value;
                var connectionName = resolveInput.Value.Contains(IdentifierValuesSeparator) ?
                    resolveInput.Value.Split(IdentifierValuesSeparator)[0] : string.Empty;

                var consolidatedResults = this.ResolveInputBulk(input, connectionName);

                if (consolidatedResults != null && consolidatedResults.Count > 0)
                {
                    resolved.Add(consolidatedResults.ElementAt(0).PickerEntity);
                    return;
                }

                if (resolveInput.ClaimType == ConnectionClaimType)
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
                else if (resolveInput.ClaimType == RoleClaimType)
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
            });
        }

        protected override void FillResolve(Uri context, string[] entityTypes, string resolveInput, List<PickerEntity> resolved)
        {
            if (!this.SetSPTrustInCurrentContext(context))
            {
                return;
            }

            SPSecurity.RunWithElevatedPrivileges(delegate
            {
                this.InitializeAuth0Client();
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

        protected override void FillSearch(Uri context, string[] entityTypes, string searchPattern, string hierarchyNodeID, int maxCount, SPProviderHierarchyTree searchTree)
        {
            if (!this.SetSPTrustInCurrentContext(context))
            {
                return;
            }

            SPProviderHierarchyNode matchNode = null;
            SPSecurity.RunWithElevatedPrivileges(delegate
            {
                this.InitializeAuth0Client();
                var consolidatedResults = this.ResolveInputBulk(searchPattern, hierarchyNodeID);

                if (consolidatedResults != null)
                {
                    if (string.IsNullOrEmpty(searchPattern))
                    {
                        // All users from specific connection(s)
                        var results = this.CreateAllUsersResults(hierarchyNodeID);
                        results.ToList().ForEach(
                            r => consolidatedResults.Add(r));
                    }
                    else if (this.alwaysResolveValue &&
                             Utils.ValidEmail(searchPattern) &&
                             !consolidatedResults.Any(
                                r => r.Auth0User.Email.Equals(searchPattern, StringComparison.OrdinalIgnoreCase) &&
                                     r.Attribute.PeoplePickerAttributeHierarchyNodeId == hierarchyNodeID))
                    {
                        // Specific email from specific connection
                        var result = this.CreateUniqueResult(searchPattern, UsersNode);
                        consolidatedResults.Add(result);
                    }

                    if (consolidatedResults.Count > 0)
                    {
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

        protected void InitializeAuth0Client()
        {
            this.auth0Config = this.configurationRepository.GetConfiguration();

            if (!this.auth0Config.IsValid)
            {
                return;
            }

            try
            {
                var clientsIds = this.auth0Config.ClientId.Split(new string[] { Environment.NewLine }, StringSplitOptions.None);
                var clientsSecrets = this.auth0Config.ClientSecret.Split(new string[] { Environment.NewLine }, StringSplitOptions.None);
                var clientIdIndex = Array.IndexOf(clientsIds, Utils.GetClaimsValue(ClientIdClaimsType));

                // if clientID was not found, use the first one configured on central admin
                if (clientIdIndex == -1)
                {
                    clientIdIndex = 0;
                }

                this.auth0Client = new Auth0.Client(
                    clientsIds[clientIdIndex],
                    clientsSecrets[clientIdIndex],
                    this.auth0Config.Domain);
            }
            catch (Exception ex)
            {
                Auth0LoggingService.WriteError(ex.ToString());
            }

            this.alwaysResolveValue = true; //this.auth0Config.AlwaysResolveUserInput;
            this.pickerEntityGroupName = this.auth0Config.PickerEntityGroupName;
        }

        protected virtual ICollection<ConsolidatedResult> ResolveInputBulk(string input, string selectedNode)
        {
            Auth0LoggingService.Write("ResolveInputBulk: input={0}, selectedNode={1}", input, selectedNode);

            if (string.IsNullOrEmpty(input))
            {
                return null;
            }

            if (this.auth0Client == null)
            {
                Auth0LoggingService.WriteError("Auth0 client was not initialized.");
                return null;
            }

            IEnumerable<Auth0.User> users = null;
            var consolidatedResults = new Collection<ConsolidatedResult>();

            try
            {
                Auth0LoggingService.Write("ResolveInputBulk: Searching for social and enterprise users.");

                var socialUsers = this.auth0Client.GetSocialUsers(input);
                var enterpriseUsers = this.auth0Client.GetEnterpriseUsers(input);

                // Distinct by user.Email
                users = socialUsers.Union(enterpriseUsers).DistinctBy(u => u.Email);

                // Log results.
                Auth0LoggingService.Write("ResolveInputBulk: Found {0}.", users != null ? users.Count() : 0);
            }
            catch (Exception ex)
            {
                Auth0LoggingService.WriteError(ex.ToString());
            }

            if (users != null)
            {
                foreach (var user in users)
                {
                    var claimAttribute = new ClaimAttribute
                    {
                        ClaimEntityType = SPClaimEntityTypes.User,
                        PeoplePickerAttributeDisplayName = UsersNode,
                        PeoplePickerAttributeHierarchyNodeId = UsersNode
                    };

                    consolidatedResults.Add(new ConsolidatedResult
                    {
                        Attribute = claimAttribute,
                        Auth0User = user,
                        PickerEntity = this.GetPickerEntity(user, SPClaimEntityTypes.User)
                    });
                }
            }

            return consolidatedResults;
        }
        protected virtual PickerEntity GetRolePickerEntity(string role)
        {
            PickerEntity pe = CreatePickerEntity();
            pe.DisplayText = string.Format("'{0}' Role", role);
            pe.Description = string.Format("[{0}] '{1}' Role", ProviderInternalName, role);
            pe.EntityType = SPClaimEntityTypes.FormsRole;
            pe.Claim = new SPClaim(RoleClaimType, role,
                Microsoft.IdentityModel.Claims.ClaimValueTypes.String,
                SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, this.associatedSPTrustedLoginProvider.Name));
            pe.IsResolved = true;
            pe.EntityGroupName = this.pickerEntityGroupName;
            return pe;
        }

        protected virtual PickerEntity GetPickerEntity(Auth0.User auth0User, string claimEntityType)
        {
            PickerEntity pe = CreatePickerEntity();
            SPClaim claim = null;

            if (claimEntityType == SPClaimEntityTypes.User)
            {
                claim = new SPClaim(
                    this.identifierClaimType,
                    string.IsNullOrEmpty(this.auth0Config.IdentifierUserField) || this.auth0Config.IdentifierUserField == "Email" ?
                        auth0User.UniqueEmail() :
                        Utils.GetPropValue(auth0User, this.auth0Config.IdentifierUserField).ToString(),
                    Microsoft.IdentityModel.Claims.ClaimValueTypes.String,
                    SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, this.associatedSPTrustedLoginProvider.Name));

                var displayText = !string.IsNullOrEmpty(auth0User.FamilyName) && !string.IsNullOrEmpty(auth0User.GivenName) ?
                    string.Format("{0} {1}", auth0User.GivenName, auth0User.FamilyName) : auth0User.Name;

                pe.DisplayText =
                    !string.IsNullOrEmpty(displayText) ?
                        string.Format("{0} ({1})", displayText, auth0User.Email) :
                        auth0User.Email;

                pe.Description = string.Format(
                    "Email: {0}; Name: {1}",
                    auth0User.Email,
                    auth0User.Name);

                pe.EntityType = SPClaimEntityTypes.User;
                pe.EntityData[PeopleEditorEntityDataKeys.DisplayName] = displayText;
                pe.EntityData[PeopleEditorEntityDataKeys.Email] = auth0User.Email;
                pe.EntityData["Picture"] = auth0User.Picture;
            }
            else if (claimEntityType == SPClaimEntityTypes.FormsRole)
            {
                claim = new SPClaim(
                    ConnectionClaimType,
                    auth0User.Identities.First().Connection,
                    Microsoft.IdentityModel.Claims.ClaimValueTypes.String,
                    SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, this.associatedSPTrustedLoginProvider.Name));

                pe.DisplayText = string.Format(
                    "All Users ({0})",
                    auth0User.Identities.First().Connection);

                pe.Description = string.Format(
                    "[{0}] All Users from '{1}'",
                    ProviderInternalName,
                    auth0User.Identities.First().Connection);

                pe.EntityType = SPClaimEntityTypes.FormsRole;
            }

            pe.Claim = claim;
            pe.IsResolved = true;
            pe.EntityGroupName = this.pickerEntityGroupName;

            return pe;
        }

        protected virtual bool SetSPTrustInCurrentContext(Uri context)
        {
            var webApp = SPWebApplication.Lookup(context);
            if (webApp == null)
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
                // The root site doesn't exist
                this.associatedSPTrustedLoginProvider = Utils.GetSPTrustAssociatedWithCP(ProviderInternalName);

                if (this.associatedSPTrustedLoginProvider != null &&
                    this.associatedSPTrustedLoginProvider.IdentityClaimTypeInformation != null)
                {
                    this.identifierClaimType = this.associatedSPTrustedLoginProvider.IdentityClaimTypeInformation.InputClaimType;
                }

                return this.associatedSPTrustedLoginProvider != null;
            }

            if (site == null)
            {
                return false;
            }

            SPUrlZone currentZone = site.Zone;
            SPIisSettings iisSettings = webApp.GetIisSettingsWithFallback(currentZone);
            site.Dispose();

            if (!iisSettings.UseTrustedClaimsAuthenticationProvider)
            {
                return false;
            }

            // Get the list of authentication providers associated with the zone
            foreach (SPAuthenticationProvider prov in iisSettings.ClaimsAuthenticationProviders)
            {
                if (prov.GetType() == typeof(Microsoft.SharePoint.Administration.SPTrustedAuthenticationProvider))
                {
                    // Check if the current SPTrustedAuthenticationProvider is associated with the claim provider
                    if (prov.ClaimProviderName == ProviderInternalName)
                    {
                        this.associatedSPTrustedLoginProvider = Utils.GetSPTrustAssociatedWithCP(ProviderInternalName);

                        if (this.associatedSPTrustedLoginProvider != null &&
                            this.associatedSPTrustedLoginProvider.IdentityClaimTypeInformation != null)
                        {
                            this.identifierClaimType = this.associatedSPTrustedLoginProvider.IdentityClaimTypeInformation.InputClaimType;
                        }

                        return this.associatedSPTrustedLoginProvider != null;
                    }
                }
            }

            return false;
        }

        private static SPProviderHierarchyNode GetParentNode(string nodeName)
        {
            return new SPProviderHierarchyNode(
                ProviderInternalName,
                nodeName,
                nodeName.ToLowerInvariant(),
                false);
        }

        private IEnumerable<Auth0.Connection> GetConnections()
        {
            return this.GetConnections(string.Empty);
        }

        private IEnumerable<Auth0.Connection> GetConnections(string connectionType)
        {
            IEnumerable<Auth0.Connection> connections = null;

            try
            {
                if (string.IsNullOrEmpty(connectionType))
                {
                    // All connections
                    connections = this.auth0Client.GetConnections();
                }
                else if (connectionType.Equals(EnterpriseHierarchyNode, StringComparison.OrdinalIgnoreCase))
                {
                    connections = this.auth0Client.GetEnterpriseConnections();
                }
                else if (connectionType.Equals(SocialHierarchyNode, StringComparison.OrdinalIgnoreCase))
                {
                    connections = this.auth0Client.GetSocialConnections();
                }

                Auth0LoggingService.Write("GetConnections: Total connections {0}", connections != null ? connections.Count() : 0);
            }
            catch (Exception ex)
            {
                Auth0LoggingService.WriteError(ex.ToString());
            }

            return connections != null ? connections : new List<Auth0.Connection>();
        }

        private ConsolidatedResult CreateUniqueResult(string email, string connectionName)
        {
            var claimAttribute = new ClaimAttribute
            {
                ClaimEntityType = SPClaimEntityTypes.User,
                PeoplePickerAttributeDisplayName = connectionName,
                PeoplePickerAttributeHierarchyNodeId = connectionName
            };

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
                Attribute = claimAttribute,
                Auth0User = user,
                PickerEntity = this.GetPickerEntity(user, SPClaimEntityTypes.User)
            };
        }

        private IEnumerable<ConsolidatedResult> CreateAllUsersResults(string selectedNode)
        {
            var results = new List<ConsolidatedResult>();
            var identities = new List<Identity>();

            var connections = this.GetConnections(selectedNode);
            foreach (var connection in connections)
            {
                identities.Add(new Identity
                {
                    Connection = connection.Name,
                    IsSocial = this.IsSocialConnection(connection.Name)
                });
            }

            foreach (var identity in identities)
            {
                var claimAttribute = new ClaimAttribute
                {
                    ClaimEntityType = SPClaimEntityTypes.FormsRole,
                    PeoplePickerAttributeDisplayName = identity.Connection,
                    PeoplePickerAttributeHierarchyNodeId = identity.Connection
                };

                var user = new Auth0.User
                {
                    Identities = new List<Identity> { identity }
                };

                results.Add(new ConsolidatedResult
                {
                    Attribute = claimAttribute,
                    Auth0User = user,
                    PickerEntity = this.GetPickerEntity(user, SPClaimEntityTypes.FormsRole)
                });
            }

            return results;
        }

        private bool IsSocialConnection(string connectionName)
        {
            return this.GetConnections(SocialHierarchyNode).Any(c => c.Name.Equals(connectionName, StringComparison.OrdinalIgnoreCase));
        }
    }
}