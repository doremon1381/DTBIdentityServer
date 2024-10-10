using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServerDbModels
{
    /// <summary>
    /// ID token or access token
    /// </summary>
    [Table($"{nameof(TokenResponsePerIdentityRequest)}s")]
    [PrimaryKey(nameof(Id))]
    public class TokenResponsePerIdentityRequest: DbTableBase
    {
        [ForeignKey(nameof(TokenResponseId))]
        public int TokenResponseId { get; set; }
        public TokenResponse TokenResponse { get; set; }

        [ForeignKey(nameof(TokenRequestHandlerId))]
        public int TokenRequestHandlerId { get; set; }
        public TokenRequestHandler TokenRequestHandler { get; set; }
    }
}
