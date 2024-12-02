#if IdentityServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace IssuerOfClaims.Models.DbModel
{
#if IdentityServer
    [Table($"{nameof(Client)}s")]
    [PrimaryKey(nameof(Id))]
#endif
    public class Client : DbTableBase<Guid>
    {
#if IdentityServer
        [Required]
#endif
        public string ClientId { get; set; }
#if IdentityServer
        [Required]
#endif
        public string ClientSecrets { get; set; }

        /// <summary>
        /// Specifies the allowed grant types (legal combinations of AuthorizationCode, Implicit, Hybrid, ResourceOwner, ClientCredentials).
        /// </summary>
#if IdentityServer
        [Required]
#endif
        public string AllowedGrantTypes { get; set; }
        public string RedirectUris { get; set; }
        public string PostLogoutRedirectUris { get; set; }
        public string FrontChannelLogoutUri { get; set; }
        public string AllowedScopes { get; set; }
        public string AuthProviderX509CertUrl { get; set; }
        public List<IdentityRequestHandler> TokenRequestHandlers { get; set; }

        public Client()
        {
            ClientId = "";
            ClientSecrets = string.Empty;
            AllowedGrantTypes = string.Empty;
            RedirectUris = string.Empty;
            PostLogoutRedirectUris = string.Empty;
            FrontChannelLogoutUri = "";
            AuthProviderX509CertUrl = "";
            AllowedScopes = string.Empty;

        }
    }
}
