using Microsoft.AspNetCore.Identity;
#if DbServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace PrMDbModels
{
#if DbServer
    [Table("IdentityUserClaims")]
    [PrimaryKey(nameof(Id))]
#endif
    public class IdentityUserClaim : IdentityUserClaim<int>, IDbTable
    {
        public PrMUser User { get; set; }
    }
}
