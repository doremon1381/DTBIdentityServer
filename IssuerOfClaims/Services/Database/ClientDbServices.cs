﻿using IssuerOfClaims.Database;
using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;
using System.Management;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public class ClientDbServices : DbTableServicesBase<Client>, IClientDbServices
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


            ValidateEntity(client, HttpStatusCode.BadRequest, $"{nameof(ClientDbServices)}: {ExceptionMessage.OBJECT_IS_NULL}");
            return client;
        }

        public Client Find(string clientId)
        {
            Client client = null;

            UsingDbSet(_Clients =>
            {
                client = _Clients.Include(c => c.TokenRequestHandlers).ThenInclude(c => c.RequestSession)
                .First(c => c.ClientId.Equals(clientId));
            });

            ValidateEntity(client, HttpStatusCode.BadRequest, $"{nameof(ClientDbServices)}: {ExceptionMessage.OBJECT_IS_NULL}");
            return client;
        }
    }

    public interface IClientDbServices : IDbContextBase<Client>
    {
        Client Find(string clientId, string clientSecret);
        Client Find(string clientId);
    }
}
