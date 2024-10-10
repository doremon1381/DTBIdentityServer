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
    /// Use TokenRequestHandler for receiving request data, storing requested parameter for issuing token and assembling response's value
    /// </summary>
    [Table("TokenRequestHandlers")]
    [PrimaryKey(nameof(Id))]
    public class TokenRequestHandler : DbTableBase
    {
        public TokenRequestSession TokenRequestSession { get; set; }

        [ForeignKey(nameof(UserId))]
        public int UserId { get; set; }
        public UserIdentity User { get; set; }
        /// <summary>
        /// Update when everything is done
        /// </summary>
        public DateTime? SuccessAt { get; set; } = null;

        public List<TokenResponsePerIdentityRequest> TokenResponsePerHandlers { get; set; } = new List<TokenResponsePerIdentityRequest>();
    }
}
