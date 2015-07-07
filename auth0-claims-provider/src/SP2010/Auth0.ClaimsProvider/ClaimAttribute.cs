namespace Auth0.ClaimsProvider
{
    using System;
    using System.Collections.Generic;

    public class ClaimAttribute
    {
        /// <summary>
        /// What represents the attribute (a user, a role, a security group, etc.)
        /// </summary>
        public string ClaimEntityType { get; set; }

        public string PeoplePickerAttributeHierarchyNodeId { get; set; }

        public string PeoplePickerAttributeDisplayName { get; set; }
    }
}