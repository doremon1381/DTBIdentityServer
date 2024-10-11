using Google.Apis.Auth.OAuth2;
using IssuerOfClaims.Database;
using IssuerOfClaims.Database.Model;
using IssuerOfClaims.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query.Internal;
using Microsoft.EntityFrameworkCore.Query;
using ServerDbModels;
using System.Linq.Expressions;
using System.Reflection;

namespace IssuerOfClaims.Services.Database
{
    public class ClientDbServices : DbTableBase<Client>, IClientDbServices
    {
        // TODO: will remove
        //private DbSet<Client> _Clients { get; set; }

        public ClientDbServices() 
            //: base(configuration)
        {
            // TODO: will remove
            //_Clients = dbModels;
        }

        // TODO: will remove
        public List<Client> GetAllClientWithRelation()
        {
            throw new NotImplementedException();
        }

        public Client GetByIdAndSecret(string id, string clientSecret)
        {
            Client client = null;

            UsingDbSet(_Clients =>
            {
                client = _Clients.First(c => c.ClientId.Equals(id) && c.ClientSecrets.Contains(clientSecret));
            });


            ValidateEntity(client, $"{this.GetType().Name}: client is null!");

            return client;
        }

        //internal static readonly MethodInfo IncludeMethodInfo = typeof(EntityFrameworkQueryableExtensions).GetTypeInfo()
        //    .GetDeclaredMethods("Include")
        //    .Single((MethodInfo mi) => mi.GetGenericArguments().Length == 2 && mi.GetParameters().Any((ParameterInfo pi) => pi.Name == "navigationPropertyPath" && pi.ParameterType != typeof(string)));

        //private IncludableQueryable<TEntity, TProperty> IncludeQuery<TEntity, TProperty>() where TEntity : class, IDbTable
        //{

        //}

        public Client GetByClientId(string id)
        {
            Client client = null;

            UsingDbSet(_Clients =>
            {
                client = _Clients.Include(c => c.TokenRequestSession).First(c => c.ClientId.Equals(id));
            });

            ValidateEntity(client, $"{this.GetType().Name}: client is null!");
            return client;
        }
    }

    //public interface IIncludableQueryable<out TEntity, out TProperty> : IQueryable<TEntity>, IEnumerable<TEntity>, IEnumerable, IQueryable
    //{
    //}

    public interface IClientDbServices : IDbContextBase<Client>
    {
        //List<PrMClient> GetAllClientWithRelation();
        Client GetByIdAndSecret(string id, string secret);
        Client GetByClientId(string id);
    }
}
