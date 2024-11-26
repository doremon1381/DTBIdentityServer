using ServerUltilities.Extensions;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities.Identity;
using IssuerOfClaims.Services.Database;
using IssuerOfClaims.Database;

namespace IssuerOfClaims
{
    internal static class AuthorizationResources
    {
        /// <summary>
        /// only use at server's initialization
        /// </summary>
        /// <param name="configuration"></param>
        /// <returns></returns>
        internal static bool CreateClient(DbContextManager dbContext)
        {
            var clientSet = dbContext.GetDbSet<Client>();
            var clients = clientSet.Count();

            if (clients == 0)
            {
                var printingManagermentServer = new Client();
                printingManagermentServer.ClientId = "ManagermentServer";
                printingManagermentServer.ClientSecrets = (new Secret("secretServer".Sha256()).Value);
                printingManagermentServer.AllowedGrantTypes = (GrantType.ClientCredentials);
                printingManagermentServer.RedirectUris = ("http://localhost:59867/" + "," + "http://127.0.0.1/login/");
                printingManagermentServer.PostLogoutRedirectUris = ("http://localhost:5173/");
                printingManagermentServer.FrontChannelLogoutUri = "http://localhost:5173/signout-oidc";
                printingManagermentServer.AllowedScopes = $"{IdentityServerConstants.StandardScopes.OpenId} {IdentityServerConstants.StandardScopes.Profile} {IdentityServerConstants.StandardScopes.Email} {Constants.CustomScope.Role} {IdentityServerConstants.StandardScopes.OfflineAccess}";

                var printingManagermentDbServer = new Client();
                printingManagermentDbServer.ClientId = "ManagermentDbServer";
                printingManagermentDbServer.ClientSecrets = (new Secret("secretServerDb".Sha256()).Value);
                printingManagermentDbServer.AllowedGrantTypes = (GrantType.ClientCredentials);
                printingManagermentDbServer.AllowedScopes = ($"{IdentityServerConstants.StandardScopes.OfflineAccess}");

                var printingManagermentWeb = new Client();
                printingManagermentWeb.ClientId = "Web1";
                printingManagermentWeb.ClientSecrets = (new Secret("secretWeb".Sha256()).Value);
                printingManagermentWeb.AllowedGrantTypes = (GrantType.AuthorizationCode);
                //printingManagermentWeb.RedirectUris = ("http://localhost:7209/callback");
                printingManagermentWeb.RedirectUris = ("http://localhost:59867/" + "," + "http://127.0.0.1/login/");
                printingManagermentWeb.PostLogoutRedirectUris = ("http://localhost:5173/");
                printingManagermentWeb.FrontChannelLogoutUri = "http://localhost:5173/signout-oidc";
                printingManagermentWeb.AllowedScopes = $"{IdentityServerConstants.StandardScopes.OpenId} {IdentityServerConstants.StandardScopes.Profile} {IdentityServerConstants.StandardScopes.Email} {Constants.CustomScope.Role} {IdentityServerConstants.StandardScopes.OfflineAccess}";

                var newClients = new List<Client>() { printingManagermentServer, printingManagermentDbServer, printingManagermentWeb };

                clientSet.AddRange(newClients);
                dbContext.SaveChanges();
            }

            return true;
        }
    }
}
