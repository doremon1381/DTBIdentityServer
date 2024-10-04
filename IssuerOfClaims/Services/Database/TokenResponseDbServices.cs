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

            using (var dbContext = CreateDbContext(configuration))
            {
                _TokenResponses = dbContext.GetDbSet<TokenResponse>();
                _TokenResponses.Add(obj);

                dbContext.SaveChanges();
            }

            return obj;
        }

        public TokenResponse CreateIdToken()
        {
            throw new NotImplementedException();
        }

        public TokenResponse CreateRefreshToken()
        {
            var obj = new TokenResponse()
            {
                TokenType = TokenType.RefreshToken
            };

            using (var dbContext = CreateDbContext(configuration))
            {
                _TokenResponses = dbContext.GetDbSet<TokenResponse>();
                _TokenResponses.Add(obj);

                dbContext.SaveChanges();
            }

            return obj;
        }

        public TokenResponse Find(string accessToken)
        {
            TokenResponse obj;

            using (var dbContext = CreateDbContext(configuration))
            {
                _TokenResponses = dbContext.GetDbSet<TokenResponse>();
                obj = _TokenResponses
                    .Where(t => t.TokenType.Equals(TokenType.AccessToken))
                    .First(t => t.Token.Equals(accessToken)) ?? new TokenResponse();

                dbContext.SaveChanges();
            }

            ValidateEntity(obj);

            return obj;
        }
    }

    public interface ITokenResponseDbServices : IDbContextBase<TokenResponse>
    {
        //TokenResponse GetResponseByUserId(int userId);
        TokenResponse CreateAccessToken();
        TokenResponse CreateIdToken();
        TokenResponse CreateRefreshToken();
        TokenResponse Find(string accessToken);
        //TokenResponse CreateTokenResponse(TokenRequestHandler session);
    }
}
