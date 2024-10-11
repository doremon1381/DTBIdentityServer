using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class RoleDbServices : DbTableBase<Role>, IRoleDbServices
    {
        //private DbSet<Role> _Roles;

        public RoleDbServices() 
            //: base(configuration)
        {
            //_PrMRoles = dbModels;
        }

        public int Count()
        {
            int count = 0;

            UsingDbSet(roles => 
            {
                count = roles.Count();
            });

            return count;
        }

        public Role GetRoleByName(string roleName)
        {
            Role role = null;
            UsingDbSet(roles =>
            { 
                role = roles.First(r => r.RoleName.Equals(roleName));
            });

            ValidateEntity(role);

            return role;
        }
    }

    public interface IRoleDbServices : IDbContextBase<Role>
    {
        int Count();
        Role GetRoleByName(string roleName);
    }
}
