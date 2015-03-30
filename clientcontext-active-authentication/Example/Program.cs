using System;
using System.Configuration;
using Auth0.SharePoint.ActiveAuthentication;

using Microsoft.SharePoint.Client;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            var authenticationClient = new SharePointActiveAuthenticationClient(
                ConfigurationManager.AppSettings["auth0:ClientId"],
                ConfigurationManager.AppSettings["auth0:Domain"],
                ConfigurationManager.AppSettings["auth0:Connection"],
                new Uri(ConfigurationManager.AppSettings["auth0:CallbackUrl"]),
                ConfigurationManager.AppSettings["username"],
                ConfigurationManager.AppSettings["password"]);
            authenticationClient.Logger = Console.WriteLine;

            var context = new ClientContext(ConfigurationManager.AppSettings["sharepointUrl"]);
            context.ExecutingWebRequest += (s, e) =>
            {
                e.WebRequestExecutor.WebRequest.CookieContainer = authenticationClient.CookieContainer;
            };

            // Create query.
            var web = context.Web;
            var lists = context.Web.Lists;

            // Load lists.
            context.Load(web,
                w => w.Url);
            context.Load(lists,
                l => l.Include(list => list.Title, list => list.Id));
            context.ExecuteQuery();

            // Loop results.
            Console.WriteLine("Lists on '{0}'", context.Web.Url);
            foreach (var list in lists)
                Console.WriteLine("> Title: {0} - ID: {1}", list.Title, list.Id.ToString("D"));
        }
    }
}
