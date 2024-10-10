using Google.Apis.Auth.OAuth2;
using IssuerOfClaims.Database;
using IssuerOfClaims.Database.Model;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class ClientDbServices : DbTableBase<Client>, IClientDbServices
    {
        //private DbSet<Client> _Clients { get; set; }

        public ClientDbServices(IConfigurationManager configuration) : base(configuration)
        {
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

    public interface IClientDbServices : IDbContextBase<Client>
    {
        //List<PrMClient> GetAllClientWithRelation();
        Client GetByIdAndSecret(string id, string secret);
        Client GetByClientId(string id);
    }
}
