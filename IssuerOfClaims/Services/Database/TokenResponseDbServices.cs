using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;
using ServerUltilities.Identity;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public class TokenResponseDbServices : DbTableServicesBase<TokenResponse>, ITokenResponseDbServices
    {
        public TokenResponseDbServices() 
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
            TokenResponse obj = null;

            await UsingDbSetAsync((_TokenResponses) => 
            {
                obj = _TokenResponses.Include(t => t.TokensPerIdentityRequests)
                    .Where(t => t.TokenType.Equals(tokenType))
                    .First(t => t.Token.Equals(token)) ?? new TokenResponse();
            });

            ValidateEntity(obj, HttpStatusCode.BadRequest, $"{nameof(TokenResponseDbServices)}: {ExceptionMessage.OBJECT_IS_NULL}");

            return obj;
        }
    }

    public interface ITokenResponseDbServices : IDbContextBase<TokenResponse>
    {
        //TokenResponse GetResponseByUserId(int userId);
        TokenResponse CreateAccessToken();
        TokenResponse CreateIdToken();
        TokenResponse CreateRefreshToken();
        Task<TokenResponse> FindAsync(string token, string tokenType);
        //TokenResponse CreateTokenResponse(TokenRequestHandler session);
    }
}
