using IssuerOfClaims.Models.DbModel;
#if IdentityServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace IssuerOfClaims.Models.DbModel
{
    /// <summary>
    ///  Store requested parameter for issuing token
    /// </summary>
#if IdentityServer
    [Table($"{nameof(IdentityRequestSession)}s")]
    [PrimaryKey(nameof(Id))]
#endif
    public class IdentityRequestSession: DbTableBase<Guid>
    {
        /// <summary>
        /// From client
        /// </summary>
        public string? CodeChallenge { get; set; } = null;
        /// <summary>
        /// use for google authorization
        /// </summary>
        public string? CodeVerifier { get; set; } = null;
        /// <summary>
        /// From client
        /// </summary>
        public string? CodeChallengeMethod { get; set; } = null;
        /// <summary>
        /// From client
        /// </summary>
        public string? Nonce { get; set; } = string.Empty;
        /// <summary>
        /// From client
        /// </summary>
        public string RedirectUri { get; set; } = string.Empty;
        /// <summary>
        /// From client
        /// </summary>
        public string Scope { get; set; } = string.Empty;

        /// <summary>
        /// One time use only, for "Authorization code flow" or "hybrid flow"
        /// </summary>        
        public string? AuthorizationCode { get; set; } = null;
        /// <summary>
        /// Value of this property is from TokenValidationPrinciples
        /// For sending token to client
        /// </summary>
        public string TokenType { get; set; } = TokenValidationPrinciples.Bearer;

        public bool IsOfflineAccess { get; set; } = false;

        [ForeignKey(nameof(IdentityRequestHandlerId))]
        public Guid IdentityRequestHandlerId { get; set; }
        //public IdentityRequestHandler IdentityRequestHandler { get; set; }
    }


    public static class TokenValidationPrinciples
    {
        /// <summary>
        /// By default, and simplest
        /// </summary>
        public const string Bearer = "bearer";
        /// <summary>
        /// https://datatracker.ietf.org/doc/html/rfc9449
        /// </summary>
        public const string ProofOfPossession = "proof_of_possession";
    }
}
