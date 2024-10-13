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
        public ClientDbServices() 
        {
        }

        public Client Find(string id, string clientSecret)
        {
            Client client = null;

            UsingDbSet(_Clients =>
            {
                client = _Clients.First(c => c.ClientId.Equals(id) && c.ClientSecrets.Contains(clientSecret));
            });


            ValidateEntity(client, $"{this.GetType().Name}: client is null!");
            return client;
        }

        public Client Find(string id)
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

    public interface IClientDbServices : IDbContextBase<Client>
    {
        Client Find(string id, string secret);
        Client Find(string id);
    }
}
