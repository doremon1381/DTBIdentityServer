using Microsoft.AspNetCore.Identity;
#if IdentityServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace ServerDbModels
{
#if IdentityServer
    [Table($"{nameof(IdentityUserRole)}s")]
    [PrimaryKey(nameof(Id))]
#endif
    public class IdentityUserRole : IdentityUserRole<Guid>, IDbTable
    {
#if IdentityServer
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
#endif
        public Guid Id { get; set; }
        public override Guid RoleId { get; set; }
        public override Guid UserId { get; set; }

        public Role Role { get; set; } = null;
        public UserIdentity User { get; set; } = null;
    }

    //[Table($"{nameof(IdentityUserClaim)}s")]
    //[PrimaryKey(nameof(Id))]
    //public class IdentityUserClaim<Guid>: IDbTable
    //{

    //}
}
