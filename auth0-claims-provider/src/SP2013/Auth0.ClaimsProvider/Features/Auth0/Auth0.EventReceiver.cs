namespace Auth0.ClaimsProvider.Features.Auth0.ClaimsProvider.Feature
{
    using System;
    using System.Runtime.InteropServices;
    using Microsoft.SharePoint;
    using Microsoft.SharePoint.Administration.Claims;

    /// <remarks>
    /// The GUID attached to this class may be used during packaging and should not be modified.
    /// </remarks>
    [Guid("cb05048e-0b47-4874-8326-2632bf2432cc")]
    public class Auth0ClaimsReceiver : SPClaimProviderFeatureReceiver
    {
        public override string ClaimProviderAssembly
        {
            get
            {
                return typeof(CustomClaimsProvider).Assembly.FullName;
            }
        }

        public override string ClaimProviderDescription
        {
            get
            {
                return "Auth0 Claims Provider for Sharepoint";
            }
        }

        public override bool ClaimProviderEnabled
        {
            get
            {
                return true;
            }
        }

        public override bool ClaimProviderUsedByDefault
        {
            get
            {
                return true;
            }
        }

        public override string ClaimProviderDisplayName
        {
            get
            {
                return CustomClaimsProvider.ProviderDisplayName;
            }
        }

        public override string ClaimProviderType
        {
            get
            {
                return typeof(CustomClaimsProvider).FullName;
            }
        }

        public override void FeatureActivated(SPFeatureReceiverProperties properties)
        {
            this.ExecBaseFeatureActivated(properties);
        }

        private void ExecBaseFeatureActivated(Microsoft.SharePoint.SPFeatureReceiverProperties properties)
        {
            // Wrapper function for base FeatureActivated. Used because base
            // keyword can lead to unverifiable code inside lambda expression.
            base.FeatureActivated(properties);
        }
    }
}