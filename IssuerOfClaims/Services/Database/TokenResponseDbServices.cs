using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class TokenResponseDbServices : DbTableBase<TokenResponse>, ITokenResponseDbServices
    {
        private DbSet<TokenResponse> _TokenResponses;
        public TokenResponseDbServices(IConfigurationManager configuration) : base(configuration)
        {
            //_TokenResponses = dbModels;
        }

        public TokenResponse CreateAccessToken()
        {
            var obj = new TokenResponse() 
            {
                TokenType = TokenType.AccessToken
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
                TokenType = TokenType.IdToken
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
                TokenType = TokenType.RefreshToken
            };

            UsingDbSetWithSaveChanges((tokenResponses) =>
            {
                tokenResponses.Add(obj);
            });

            return obj;
        }

        public TokenResponse Find(string accessToken, string tokenType)
        {
            TokenResponse obj;

            using (var dbContext = CreateDbContext())
            {
                _TokenResponses = dbContext.GetDbSet<TokenResponse>();
                obj = _TokenResponses.Include(t => t.TokenResponsePerHandler)
                    .Where(t => t.TokenType.Equals(tokenType))
                    .First(t => t.Token.Equals(accessToken)) ?? new TokenResponse();

                dbContext.SaveChanges();
            }

            ValidateEntity(obj, $"{this.GetType().Name}: token is null!");

            return obj;
        }
    }

    public interface ITokenResponseDbServices : IDbContextBase<TokenResponse>
    {
        //TokenResponse GetResponseByUserId(int userId);
        TokenResponse CreateAccessToken();
        TokenResponse CreateIdToken();
        TokenResponse CreateRefreshToken();
        TokenResponse Find(string accessToken, string tokenType);
        //TokenResponse CreateTokenResponse(TokenRequestHandler session);
    }
}
