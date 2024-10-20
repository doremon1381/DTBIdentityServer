using Microsoft.AspNetCore.Identity;
#if IdentityServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace ServerDbModels
{
#if IdentityServer
    [Table($"{nameof(Role)}s")]
    [PrimaryKey(nameof(Id))]
#endif
    public class Role: IdentityRole<Guid>, IDbTable
    {
        public string RoleCode { get; set; }
        public string RoleName { get; set; }
#if IdentityServer
        [NotMapped]
#endif
        public override string? Name { get; set; }
#if IdentityServer
        [NotMapped]
#endif
        public override string? NormalizedName { get; set; }
        public override string? ConcurrencyStamp { get; set; }

        public List<IdentityUserRole> IdentityUserRoles { get; set; }
    }
}
