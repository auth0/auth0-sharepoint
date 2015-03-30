# Client Context Active Authentication

This library will authenticate to Auth0 using the `/trust/usernamemixed` endpoint after which it will receive a response which will modified (to be compatible with SharePoint) and posted to SharePoint's trust endpoint.
After processing this response SharePoint will hand out a `FedAuth` cookie which can be used to authenticate calls made with the ClientContext (the Client Side Object Model).

## Configuring the application

The `/trust/usernamemixed` endpoint requires one or more client aliasses to be set on the application in Auth0. Currently the dashboard does not allow setting these so you'll need to use [the API](https://auth0.com/docs/apiv2#!/clients/patch_clients_by_id) to add the client aliasses to the application.

Here's an example:

```
{
   "client_aliases": ["http://sp.fabrikamcorp.com/_trust/"]
}
```

*This must point to the trust endpoint of the SharePoint deployment you'll be using.* 

## Running the sample

Before you can run the sample you'll need to set the following keys in the app.config:

```xml
    <add key="auth0:ClientId" value="CLIENT_ID" />
    <add key="auth0:Domain" value="YOU.auth0.com" />
    <add key="auth0:Connection" value="YOUR-CONNECTION-NAME" />
    <add key="auth0:CallbackUrl" value="http://YOUR-SP/_trust/" />

    <add key="username" value="john" />
    <add key="password" value="abc" />
    <add key="sharepointUrl" value="http://YOUR-SP" />
```
