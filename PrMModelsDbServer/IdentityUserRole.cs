using Microsoft.AspNetCore.Identity;
#if IdentityServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace ServerDbModels
{
#if IdentityServer
    [Table("IdentityUserRoles")]
    [PrimaryKey(nameof(Id))]
#endif
    public class IdentityUserRole : IdentityUserRole<int>, IDbTable
    {
#if IdentityServer
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
#endif
        public int Id { get; set; }
        public override int RoleId { get; set; }
        public override int UserId { get; set; }

        public Role Role { get; set; } = null;
        public UserIdentity User { get; set; } = null;
    }
}
