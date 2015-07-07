namespace Auth0.ClaimsProvider
{
    using Microsoft.SharePoint.WebControls;

    public class ConsolidatedResult
    {
        public ClaimAttribute Attribute { get; set; }

        public Auth0.User Auth0User { get; set; }

        public PickerEntity PickerEntity { get; set; }
    }
}