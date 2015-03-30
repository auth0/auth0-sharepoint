using System;
using System.IdentityModel.Protocols.WSTrust;
using System.ServiceModel.Channels;
using System.Xml;

namespace Auth0.SharePoint.ActiveAuthentication
{
    internal class RequestBodyWriter : BodyWriter
    {
        private readonly RequestSecurityToken _rst;
        private readonly WSTrustRequestSerializer _serializer;

        public RequestBodyWriter(WSTrustRequestSerializer serializer, RequestSecurityToken rst)
            : base(false)
        {
            if (serializer == null)
                throw new ArgumentNullException("serializer");
            _serializer = serializer;
            _rst = rst;
        }

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            _serializer.WriteXml(_rst, writer, new WSTrustSerializationContext());
        }
    }
}