using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class RoleDbServices : DbTableBase<Role>, IRoleDbServices
    {
        private DbSet<Role> _Roles;

        public RoleDbServices(IConfigurationManager configuration) : base(configuration)
        {
            //_PrMRoles = dbModels;
        }

        public int Count()
        {
            int count = 0;

            using (var dbContext = CreateDbContext(configuration))
            {
                _Roles = dbContext.GetDbSet<Role>();
                count = _Roles.Count();
            }

            return count;
        }

        public Role GetRoleByName(string roleName)
        {
            Role role;
            using (var dbContext = CreateDbContext(configuration))
            {
                _Roles = dbContext.GetDbSet<Role>();
                role = _Roles.First(r => r.RoleName.Equals(roleName));
            }

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
