using Microsoft.EntityFrameworkCore;
using ServerDbModels;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public class RoleDbServices : DbTableServicesBase<Role>, IRoleDbServices
    {

        public RoleDbServices() 
        {
        }

        public int Count()
        {
            int count = 0;

            UsingDbSetAsync(roles => 
            {
                count = roles.Count();
            });

            return count;
        }

        public Role GetRoleByName(string roleName)
        {
            Role role = null;
            UsingDbSetAsync(roles =>
            { 
                role = roles.First(r => r.RoleName.Equals(roleName));
            });

            ValidateEntity(role, HttpStatusCode.NotFound);

            return role;
        }
    }

    public interface IRoleDbServices : IDbContextBase<Role>
    {
        int Count();
        Role GetRoleByName(string roleName);
    }
}
