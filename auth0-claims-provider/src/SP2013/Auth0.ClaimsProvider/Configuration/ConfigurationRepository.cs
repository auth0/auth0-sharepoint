namespace Auth0.ClaimsProvider.Configuration
{
    using System;
    using System.Collections.Generic;
    using Microsoft.SharePoint.Administration;
    using Microsoft.SharePoint.Administration.Claims;
    using Microsoft.SharePoint.WebControls;

    public class ConfigurationRepository : IConfigurationRepository
    {
        public const string Auth0PersistedObjectName = "Auth0ClaimsProviderConfig";

        public Auth0Config GetConfiguration()
        {
            var configuration = SPFarm.Local.GetChild<Auth0Config>(Auth0PersistedObjectName) ??
                                CreatePersistedObject();

            if (string.IsNullOrEmpty(configuration.PickerEntityGroupName))
            {
                configuration.PickerEntityGroupName = "Results";
            }

            if (string.IsNullOrEmpty(configuration.IdentifierUserField))
            {
                configuration.IdentifierUserField = "Email";
            }

            return configuration;
        }

        public void SaveConfiguration(Auth0Config auth0Config)
        {
            if (auth0Config != null)
            {
                auth0Config.Update();
            }
        }

        private static Auth0Config CreatePersistedObject()
        {
            var persistedObject = new Auth0Config(Auth0PersistedObjectName, SPFarm.Local);
            persistedObject.Update();

            return persistedObject;
        }
    }
}