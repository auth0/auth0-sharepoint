namespace Auth0.ClaimsProvider.Core.Model
{
    using Microsoft.SharePoint.WebControls;

    public class ConsolidatedResult
    {
        public ClaimAttribute Attribute { get; set; }

        public Auth0.User User { get; set; }

        public PickerEntity PickerEntity { get; set; }
    }
}