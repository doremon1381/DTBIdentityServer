﻿using Azure.Core;
using IssuerOfClaims.Database;
using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;
using System.Net;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Services.Database
{
    public class TokenForRequestHandlerDbServices : DbTableServicesBase<TokenForRequestHandler>, ITokenForRequestHandlerDbServices
    {
        public TokenForRequestHandlerDbServices() 
        {
        }

        public TokenForRequestHandler CreatNew()
        {
            var obj = new TokenForRequestHandler();

            UsingDbSetWithSaveChanges(_tokenResponses => 
            {
                _tokenResponses.Add(obj);
            });

            return obj;
        }

        public TokenForRequestHandler GetDraftObject()
        {
            var obj = new TokenForRequestHandler();
            return obj;
        }

        public TokenForRequestHandler FindByAccessToken(string accessToken)
        {
            TokenForRequestHandler obj = null;

            UsingDbSet(_tokenResponses => 
            {
                obj = _tokenResponses
                    .Include(t => t.TokenResponse)
                    .Include(t => t.IdentityRequestHandler).ThenInclude(h => h.User)
                    .Where(t => t.TokenResponse.TokenType.Equals(TokenTypes.AccessToken))
                    .First(r => r.TokenResponse.Token.Equals(accessToken));
            });

            ValidateEntity(obj, HttpStatusCode.BadRequest, $"{nameof(TokenForRequestHandlerDbServices)}: {ExceptionMessage.OBJECT_IS_NULL}");

            return obj;
        }

        /// <summary>
        /// TODO: local authentication will not use token from external source
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="clientId"></param>
        /// <param name="needAccessToken"></param>
        /// <param name="issuedByLocal"></param>
        /// <returns></returns>
        public TokenForRequestHandler? FindLast(Guid userId, Guid clientId, bool needAccessToken = true, bool issuedByLocal = true)
        {
            var filter = needAccessToken switch
            {
                true => new Func<TokenForRequestHandler, bool>((t) => t.TokenResponse.TokenType.Equals(TokenTypes.AccessToken) && t.TokenResponse.ExternalSource == string.Empty),
                false => new Func<TokenForRequestHandler, bool>((t) => t.TokenResponse.TokenType.Equals(TokenTypes.RefreshToken) && t.TokenResponse.ExternalSource == string.Empty)
            };

            TokenForRequestHandler? obj = null;
            UsingDbSet(_tokenResponses => 
            {
                obj = _tokenResponses
                        .Include(t => t.TokenResponse)
                        .Include(t => t.IdentityRequestHandler).ThenInclude(h => h.RequestSession)
                        .Where(filter)
                        .LastOrDefault(t => t.IdentityRequestHandler.UserId == userId && t.IdentityRequestHandler.ClientId == clientId);
            });

            // TODO:
            //ValidateEntity(obj, $"{this.GetType().Name}: Something is wrong!");

            return obj;
        }
    }

    public interface ITokenForRequestHandlerDbServices : IDbContextBase<TokenForRequestHandler>
    {
        TokenForRequestHandler GetDraftObject();
        TokenForRequestHandler FindByAccessToken(string accessToken);
        TokenForRequestHandler CreatNew();
        TokenForRequestHandler? FindLast(Guid userId, Guid clientId, bool needAccessToken = true, bool issuedByLocal = true);
    }
}
