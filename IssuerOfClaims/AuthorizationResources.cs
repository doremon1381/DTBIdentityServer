using ServerUltilities.Extensions;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;
using ServerUltilities.Identity;
using IssuerOfClaims.Services.Database;
using IssuerOfClaims.Database;

namespace IssuerOfClaims
{
    public static class AuthorizationResources
    {
        /// <summary>
        /// only use at server's initialization
        /// </summary>
        /// <param name="configuration"></param>
        /// <returns></returns>
        internal static bool CreateClient(IConfigurationManager configuration)
        {
            //DbContextManager dbContext = CreateDbContext(configuration);

            var clientDb = new ClientDbServices();
            var clients = clientDb.GetAll();

            if (clients.Count == 0)
            {
                var printingManagermentServer = new Client();
                printingManagermentServer.ClientId = "ManagermentServer";
                printingManagermentServer.ClientSecrets = (new Secret("secretServer".Sha256()).Value);
                printingManagermentServer.AllowedGrantTypes = (GrantType.ClientCredentials);
                printingManagermentServer.RedirectUris = ("http://localhost:59867/" + "," + "http://127.0.0.1/login/");
                printingManagermentServer.PostLogoutRedirectUris = ("http://localhost:5173/");
                printingManagermentServer.FrontChannelLogoutUri = "http://localhost:5173/signout-oidc";
                printingManagermentServer.AllowedScopes = $"{IdentityServerConstants.StandardScopes.OpenId} {IdentityServerConstants.StandardScopes.Profile} {IdentityServerConstants.StandardScopes.Email} {Constants.CustomScope.Role} {IdentityServerConstants.StandardScopes.OfflineAccess}";
                //"api1", "api2.read_only"

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

                clientDb.AddMany(newClients);

                clients = newClients;
            }

            //var roles = dbContext.Roles.ToList();

            return true;
        }

        private static DbContextManager CreateDbContext(IConfigurationManager configuration)
        {
            var contextOptions = new DbContextOptionsBuilder<DbContextManager>()
                 .UseSqlServer(configuration.GetConnectionString(DbUtilities.DatabasePath))
                 .Options;

            var dbContext = new DbContextManager(contextOptions, null);
            return dbContext;
        }
    }
}
