using System;
using System.Net.Security;
using System.ServiceModel;
using System.ServiceModel.Channels;

namespace Auth0.SharePoint.ActiveAuthentication
{
    [ServiceContract]
    internal interface IWsTrustFeb2005Contract
    {
        [OperationContract(ProtectionLevel = ProtectionLevel.EncryptAndSign,
            Action = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue",
            ReplyAction = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue", AsyncPattern = true)]
        IAsyncResult BeginIssue(Message request, AsyncCallback callback, object state);

        Message EndIssue(IAsyncResult asyncResult);
    }
}