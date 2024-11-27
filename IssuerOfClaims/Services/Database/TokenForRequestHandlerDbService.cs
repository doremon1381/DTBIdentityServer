using Azure.Core;
using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities.Extensions;
using System.Net;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Services.Database
{
    public class TokenForRequestHandlerDbService : DbTableServicesBase<TokenForRequestHandler>, ITokenForRequestHandlerDbService
    {
        public TokenForRequestHandlerDbService(IServiceProvider serviceProvider) : base(serviceProvider) 
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
                    //.AsSplitQuery()
                    .AsNoTracking()
                    .First();
            });

            ValidateEntity(obj, HttpStatusCode.BadRequest, $"{nameof(TokenForRequestHandlerDbService)}: {ExceptionMessage.OBJECT_IS_NULL}");

            return obj;
        }

        /// <summary>
        /// TODO: local authentication will not use token from external source
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="clientId"></param>
        /// <param name="isAccessToken"></param>
        /// <param name="issuedByLocal"></param>
        /// <returns></returns>
        public async Task<TokenForRequestHandler>? FindLastAsync(Guid userId, Guid clientId, bool isAccessToken = true, bool issuedByLocal = true)
        {
            var tokenType = isAccessToken switch
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
                                && t.TokenResponse.TokenType.Equals(tokenType)
                                && t.TokenResponse.ExternalSource == string.Empty)
                        .OrderBy(t => t.Id)
                        //.AsSplitQuery()
                        .AsNoTracking()
                        .LastOrDefault();
            });

            // TODO:
            //ValidateEntity(obj, $"{this.GetType().Name}: Something is wrong!");

            return obj;
        }
    }

    public interface ITokenForRequestHandlerDbService : IDbContextBase<TokenForRequestHandler>
    {
        TokenForRequestHandler GetDraftObject();
        Task<TokenForRequestHandler> FindByAccessTokenASync(string accessToken);
        TokenForRequestHandler CreatNew();
        Task<TokenForRequestHandler>? FindLastAsync(Guid userId, Guid clientId, bool isAccessToken = true, bool issuedByLocal = true);
    }
}
