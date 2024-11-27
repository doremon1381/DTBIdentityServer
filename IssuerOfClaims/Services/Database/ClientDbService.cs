using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities.Extensions;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public class ClientDbService : DbTableServicesBase<Client>, IClientDbService
    {
        public ClientDbService(IServiceProvider serviceProvider) : base(serviceProvider)
        {

        }

        public async Task<Client> FindAsync(string id, string clientSecret)
        {
            Client client = null;

            await UsingDbSetAsync(_Clients =>
            {
                client = _Clients
                    .AsNoTracking()
                    .Where(c => c.ClientId.Equals(id) && c.ClientSecrets.Contains(clientSecret))
                    .First();
            });

            ValidateEntity(client, HttpStatusCode.BadRequest, $"{nameof(ClientDbService)}: {ExceptionMessage.OBJECT_IS_NULL}");
            return client;
        }

        public async Task<Client> FindAsync(string clientId)
        {
            Client client = null;

            await UsingDbSetAsync((_Clients) =>
            {
                client = _Clients
                .AsNoTracking()
                // TODO: will debug to know how in this step, the query result size can be around 40MB...
                //.Include(c => c.TokenRequestHandlers).ThenInclude(c => c.RequestSession)
                .Where(c => c.ClientId.Equals(clientId))
                .First();
            });

            ValidateEntity(client, HttpStatusCode.BadRequest, $"{nameof(ClientDbService)}: {ExceptionMessage.OBJECT_IS_NULL}");
            return client;
        }
    }

    public interface IClientDbService : IDbContextBase<Client>
    {
        Task<Client> FindAsync(string clientId, string clientSecret);
        Task<Client> FindAsync(string clientId);
    }
}
