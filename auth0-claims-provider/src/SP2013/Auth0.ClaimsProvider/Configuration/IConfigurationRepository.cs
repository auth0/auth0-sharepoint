namespace Auth0.ClaimsProvider.Configuration
{
    using System;

    public interface IConfigurationRepository
    {
        Auth0Config GetConfiguration();

        void SaveConfiguration(Auth0Config auth0Config);
    }
}