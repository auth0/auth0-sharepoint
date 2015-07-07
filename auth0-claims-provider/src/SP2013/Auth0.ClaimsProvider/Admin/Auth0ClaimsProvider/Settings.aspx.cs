namespace Auth0.ClaimsProvider.AdminWeb
{
    using System;
    using Auth0.ClaimsProvider.Configuration;
    using Microsoft.SharePoint;
    using Microsoft.SharePoint.Administration.Claims;
    using Microsoft.SharePoint.ApplicationPages;

    public partial class Settings : OperationsPage
    {
        private const string TextErrorNoTrustAssociation = "Auth0 is currently not associated with any TrustedLoginProvider. It is mandatory because it cannot create permission for a trust if it is not associated to it.<br/>Visit <a href=\"https://github.com/auth0/sharepoint-claimsprovider\" target=\"_blank\">https://github.com/auth0/sharepoint-claimsprovider</a> to see how to associate it.<br/>Settings on this page will not be available as long as Auth0 Claims Provider will not associated to a trust.";
        private const string TextErrorFieldsMissing = "Some mandatory fields are missing.";

        private SPTrustedLoginProvider currentTrustedLoginProvider;
        private IConfigurationRepository configurationRepository = new ConfigurationRepository();

        protected void Page_Load(object sender, EventArgs e)
        {
            // Get trust currently associated with Auth0, if any
            this.currentTrustedLoginProvider = Utils.GetSPTrustedLoginProviderForClaimsProvider(CustomClaimsProvider.ProviderInternalName);
            if (this.currentTrustedLoginProvider == null)
            {
                // Claim provider is currently not associated with any trust.
                // Display a message in the page and disable controls
                this.LabelErrorMessage.Text = TextErrorNoTrustAssociation;
                this.BtnOK.Enabled = false;
                return;
            }

            if (!this.IsPostBack)
            {
                this.PopulateFields();
            }
        }

        protected void UpdateConfiguration()
        {
            if (this.currentTrustedLoginProvider == null)
            {
                // string.Format("Trust associated with Auth0 Claims Provider could not be found.", Auth0Config.PersistedObjectName)
                return;
            }

            // Update object in database
            SPSecurity.RunWithElevatedPrivileges(delegate
            {
                this.Web.AllowUnsafeUpdates = true;
                var auth0Config = this.configurationRepository.GetConfiguration();
                auth0Config.Domain = this.DomainTextBox.Text;
                auth0Config.ClientId = this.ClientIdTextBox.Text;
                auth0Config.ClientSecret = this.ClientSecretTextBox.Text;
                auth0Config.IdentifierUserField = this.IdentifierUserFieldTextBox.Text;
                auth0Config.PickerEntityGroupName = this.PickerEntityGroupNameTextBox.Text;
                this.configurationRepository.SaveConfiguration(auth0Config);
                this.Web.AllowUnsafeUpdates = false;

                // string.Format("Updated Auth0 Claims Provider configuration through PersistedObject {0}.", Auth0Config.PersistedObjectName)
            });
        }

        protected void BtnOK_Click(object sender, EventArgs e)
        {
            // Validate settings
            if (string.IsNullOrEmpty(this.DomainTextBox.Text.Trim()) ||
                string.IsNullOrEmpty(this.ClientIdTextBox.Text.Trim()) ||
                string.IsNullOrEmpty(this.ClientSecretTextBox.Text.Trim()) ||
                string.IsNullOrEmpty(this.IdentifierUserFieldTextBox.Text.Trim()))
            {
                this.LabelErrorMessage.Text = TextErrorFieldsMissing;
                return;
            }

            this.UpdateConfiguration();
            this.RedirectToOperationsPage();
        }

        private void PopulateFields()
        {
            Auth0Config auth0Config = null;
            SPSecurity.RunWithElevatedPrivileges(delegate
            {
                // Get SPPersisted Object
                this.Web.AllowUnsafeUpdates = true;
                auth0Config = this.configurationRepository.GetConfiguration();
                this.Web.AllowUnsafeUpdates = false;
            });

            if (auth0Config != null)
            {
                this.DomainTextBox.Text = auth0Config.Domain;
                this.ClientIdTextBox.Text = auth0Config.ClientId;
                this.ClientSecretTextBox.Text = auth0Config.ClientSecret;
                this.IdentifierUserFieldTextBox.Text = auth0Config.IdentifierUserField;
                this.PickerEntityGroupNameTextBox.Text = auth0Config.PickerEntityGroupName;
            }
        }
    }
}