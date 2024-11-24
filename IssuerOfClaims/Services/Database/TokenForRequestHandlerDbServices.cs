using Azure.Core;
using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities.Extensions;
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

        public async Task<TokenForRequestHandler> FindByAccessTokenASync(string accessToken)
        {
            TokenForRequestHandler obj = null;

            await UsingDbSetAsync(_tokenResponses => 
            {
                obj = _tokenResponses
                    .Include(t => t.TokenResponse)
                    .Include(t => t.IdentityRequestHandler).ThenInclude(h => h.User)
                    .Where(t => t.TokenResponse.TokenType.Equals(TokenTypes.AccessToken))
                    .AsSplitQuery()
                    .First();
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
        public async Task<TokenForRequestHandler>? FindLastAsync(Guid userId, Guid clientId, bool needAccessToken = true, bool issuedByLocal = true)
        {
            //var filter = needAccessToken switch
            //{
            //    true => new Func<TokenForRequestHandler, bool>((t) => t.TokenResponse.TokenType.Equals(TokenTypes.AccessToken) && t.TokenResponse.ExternalSource == string.Empty),
            //    false => new Func<TokenForRequestHandler, bool>((t) => t.TokenResponse.TokenType.Equals(TokenTypes.RefreshToken) && t.TokenResponse.ExternalSource == string.Empty)
            //};
                    
            var filter = needAccessToken switch
            {
                true => TokenTypes.AccessToken,
                false => TokenTypes.RefreshToken
            };

            TokenForRequestHandler? obj = null;
            await UsingDbSetAsync(_tokenResponses => 
            {
                obj = _tokenResponses
                        .Include(t => t.TokenResponse)
                        .Include(t => t.IdentityRequestHandler).ThenInclude(h => h.RequestSession)
                        .Where(t => t.IdentityRequestHandler.UserId == userId 
                                && t.IdentityRequestHandler.ClientId == clientId
                                && t.TokenResponse.TokenType.Equals(filter)
                                && t.TokenResponse.ExternalSource == string.Empty)
                        .OrderBy(t => t.Id)
                        .AsSplitQuery()
                        .LastOrDefault();
            });

            // TODO:
            //ValidateEntity(obj, $"{this.GetType().Name}: Something is wrong!");

            return obj;
        }
    }

    public interface ITokenForRequestHandlerDbServices : IDbContextBase<TokenForRequestHandler>
    {
        TokenForRequestHandler GetDraftObject();
        Task<TokenForRequestHandler> FindByAccessTokenASync(string accessToken);
        TokenForRequestHandler CreatNew();
        Task<TokenForRequestHandler>? FindLastAsync(Guid userId, Guid clientId, bool needAccessToken = true, bool issuedByLocal = true);
    }
}
