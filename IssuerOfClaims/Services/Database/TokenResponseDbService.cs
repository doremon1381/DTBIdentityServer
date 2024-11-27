using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities.Extensions;
using ServerUltilities.Identity;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public class TokenResponseDbService : DbTableServicesBase<TokenResponse>, ITokenResponseDbService
    {
        public TokenResponseDbService(IServiceProvider serviceProvider) : base(serviceProvider) 
        {
        }

        public TokenResponse CreateAccessToken()
        {
            var obj = new TokenResponse() 
            {
                TokenType = OidcConstants.TokenTypes.AccessToken
            };

            UsingDbSetWithSaveChanges((tokenResponses) =>
            {
                tokenResponses.Add(obj);
            });

            return obj;
        }

        public TokenResponse CreateIdToken()
        {
            var obj = new TokenResponse()
            {
                TokenType = OidcConstants.TokenTypes.IdentityToken
            };

            UsingDbSetWithSaveChanges((tokenResponses) =>
            {
                tokenResponses.Add(obj);
            });

            return obj;
        }

        public TokenResponse CreateRefreshToken()
        {
            var obj = new TokenResponse()
            {
                TokenType = OidcConstants.TokenTypes.RefreshToken
            };

            UsingDbSetWithSaveChanges((tokenResponses) =>
            {
                tokenResponses.Add(obj);
            });

            return obj;
        }

        public async Task<TokenResponse> FindAsync(string token, string tokenType)
        {
            TokenResponse? obj = null;

            await UsingDbSetAsync((_TokenResponses) => 
            {
                obj = _TokenResponses.Include(t => t.TokensPerIdentityRequests)
                    .Where(t => t.TokenType.Equals(tokenType) && t.Token.Equals(token))
                    .AsNoTracking()
                    .First() ?? null;
            });

            ValidateEntity(obj, HttpStatusCode.BadRequest, $"{nameof(TokenResponseDbService)}: {ExceptionMessage.OBJECT_IS_NULL}");

            return obj;
        }
    }

    public interface ITokenResponseDbService : IDbContextBase<TokenResponse>
    {
        TokenResponse CreateAccessToken();
        TokenResponse CreateIdToken();
        TokenResponse CreateRefreshToken();
        Task<TokenResponse> FindAsync(string token, string tokenType);
    }
}
