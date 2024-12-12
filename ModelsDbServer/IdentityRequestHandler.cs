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
    /// Use TokenRequestHandler for receiving request data, storing requested parameter for issuing token and assembling response's value
    /// </summary>
    [Table($"{nameof(IdentityRequestHandler)}s")]
    [PrimaryKey(nameof(Id))]
    public class IdentityRequestHandler : DbTableBase<Guid>
    {
        public IdentityRequestSession RequestSession { get; set; }

        [ForeignKey(nameof(UserId))]
        public Guid? UserId { get; set; }
        public UserIdentity? User { get; set; }

        /// <summary>
        /// TODO: intend to use this login session with client, cause 
        /// </summary>
        [ForeignKey(nameof(ClientId))]
        public Guid ClientId { get; set; }
        public Client Client { get; set; }

        /// <summary>
        /// Update when everything is done
        /// <para>Remove IsInLoginSession inside IdentityRequestSession because when the handler session is success, then no need another property inside session</para>
        /// </summary>
        public DateTime? SuccessAt { get; set; } = null;

        public List<TokenForRequestHandler> TokensPerRequestHandlers { get; set; }
    }
}
