using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities.Extensions;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public class ClientDbServices : DbTableServicesBase<Client>, IClientDbServices
    {
        public ClientDbServices()
        {
        }

        public async Task<Client> FindAsync(string id, string clientSecret)
        {
            Client client = null;

            await UsingDbSetAsync(_Clients =>
            {
                client = _Clients
                    // TODO: temporary
                    .AsNoTracking()
                    .First(c => c.ClientId.Equals(id) && c.ClientSecrets.Contains(clientSecret));
            });


            ValidateEntity(client, HttpStatusCode.BadRequest, $"{nameof(ClientDbServices)}: {ExceptionMessage.OBJECT_IS_NULL}");
            return client;
        }

        public async Task<Client> FindAsync(string clientId)
        {
            Client client = null;

            await UsingDbSetAsync((_Clients) =>
            {
                client = _Clients
                // TODO: temporary
                .AsNoTracking()
                .Include(c => c.TokenRequestHandlers).ThenInclude(c => c.RequestSession)
                .First(c => c.ClientId.Equals(clientId));
            });

            ValidateEntity(client, HttpStatusCode.BadRequest, $"{nameof(ClientDbServices)}: {ExceptionMessage.OBJECT_IS_NULL}");
            return client;
        }
    }

    public interface IClientDbServices : IDbContextBase<Client>
    {
        Task<Client> FindAsync(string clientId, string clientSecret);
        Task<Client> FindAsync(string clientId);
    }
}
