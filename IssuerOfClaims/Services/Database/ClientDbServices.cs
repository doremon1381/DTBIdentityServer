using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

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

        public Client Find(string clientId)
        {
            Client client = null;

            UsingDbSet(_Clients =>
            {
                client = _Clients.Include(c => c.TokenRequestSession).First(c => c.ClientId.Equals(clientId));
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
