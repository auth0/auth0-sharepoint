using System;
using System.ServiceModel;
using System.ServiceModel.Channels;

namespace Auth0.SharePoint.ActiveAuthentication
{
    internal class WsTrustFeb2005ContractClient : ClientBase<IWsTrustFeb2005Contract>, IWsTrustFeb2005Contract
    {
        public WsTrustFeb2005ContractClient(Binding binding, EndpointAddress remoteAddress)
            : base(binding, remoteAddress)
        {
        }

        public IAsyncResult BeginIssue(Message request, AsyncCallback callback, object state)
        {
            return Channel.BeginIssue(request, callback, state);
        }

        public Message EndIssue(IAsyncResult asyncResult)
        {
            return Channel.EndIssue(asyncResult);
        }
    }
}