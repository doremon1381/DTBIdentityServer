using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace IssuerOfClaims.Models.DbModel
{
    [Table($"{nameof(TokenResponse)}s")]
    [PrimaryKey(nameof(Id))]
    public class TokenResponse : DbTableBase<Guid>
    {
        public string Token { get; set; } = string.Empty;

        public string TokenType { get; set; } = string.Empty;

        public string ExternalSource { get; set;} = string.Empty;

        /// <summary>
        /// TODO: set by seconds
        /// </summary>
        public DateTime TokenExpiried { get; set; }
        public DateTime? IssueAt { get; set; }

        public List<TokenForRequestHandler> TokensPerIdentityRequests { get; set; }
    }
}
