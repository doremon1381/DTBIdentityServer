using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IssuerOfClaims.Models.DbModel
{
    /// <summary>
    /// ID token or access token
    /// </summary>
    [Table($"{nameof(TokenForRequestHandler)}s")]
    [PrimaryKey(nameof(Id))]
    public class TokenForRequestHandler: DbTableBase<Guid>
    {
        [ForeignKey(nameof(TokenResponseId))]
        public Guid TokenResponseId { get; set; }
        public TokenResponse TokenResponse { get; set; }

        [ForeignKey(nameof(IdentityRequestHandlerId))]
        public Guid IdentityRequestHandlerId { get; set; }
        public IdentityRequestHandler IdentityRequestHandler { get; set; }
    }
}
