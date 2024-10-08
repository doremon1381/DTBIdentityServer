using Azure.Core;
using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class TokenResponsePerHandlerDbServices : DbTableBase<TokenResponsePerIdentityRequest>, ITokenResponsePerHandlerDbServices
    {
        private DbSet<TokenResponsePerIdentityRequest> _tokenResponses { get; set; }

        public TokenResponsePerHandlerDbServices(IConfigurationManager configuration) : base(configuration)
        {
            //_tokenResponsePerHandlers = this.dbModels;
        }

        public TokenResponsePerIdentityRequest CreatNew()
        {
            var obj = new TokenResponsePerIdentityRequest();

            using (var dbContext = CreateDbContext())
            {
                _tokenResponses = dbContext.GetDbSet<TokenResponsePerIdentityRequest>();

                _tokenResponses.Add(obj);
                dbContext.SaveChanges();
            }

            return obj;
        }

        public TokenResponsePerIdentityRequest GetDraftObject()
        {
            var obj = new TokenResponsePerIdentityRequest();
            return obj;
        }

        public TokenResponsePerIdentityRequest FindByAccessToken(string accessToken)
        {
            TokenResponsePerIdentityRequest obj;

            using (var dbContext = CreateDbContext())
            {
                _tokenResponses = dbContext.GetDbSet<TokenResponsePerIdentityRequest>();

                obj = _tokenResponses
                    .Include(t => t.TokenResponse)
                    .Include(t => t.TokenRequestHandler).ThenInclude(h => h.User)
                    .Where(t => t.TokenResponse.TokenType.Equals(TokenType.AccessToken))
                    .First(r => r.TokenResponse.Token.Equals(accessToken));
            }

            ValidateEntity(obj, $"{this.GetType().Name}: Something is wrong!");

            return obj;
        }

        public TokenResponsePerIdentityRequest FindLast(int userId, int clientId, bool needAccessToken = true, bool issuedByLocal = true)
        {
            var filter = needAccessToken switch
            {
                true => new Func<TokenResponsePerIdentityRequest, bool>((t) => t.TokenResponse.TokenType.Equals(TokenType.AccessToken)),
                false => new Func<TokenResponsePerIdentityRequest, bool>((t) => t.TokenResponse.TokenType.Equals(TokenType.RefreshToken))
            };

            TokenResponsePerIdentityRequest obj;
            using (var dbContext = CreateDbContext())
            {
                _tokenResponses = dbContext.GetDbSet<TokenResponsePerIdentityRequest>();

                obj = _tokenResponses
                    .Include(t => t.TokenResponse)
                    .Include(t => t.TokenRequestHandler).ThenInclude(h => h.TokenRequestSession)
                    .Where(filter)
                    .LastOrDefault(t => t.TokenRequestHandler.UserId == userId && t.TokenRequestHandler.TokenRequestSession.ClientId == clientId);
            }

            // TODO:
            //ValidateEntity(obj, $"{this.GetType().Name}: Something is wrong!");

            return obj;
        }
    }

    public interface ITokenResponsePerHandlerDbServices : IDbContextBase<TokenResponsePerIdentityRequest>
    {
        TokenResponsePerIdentityRequest GetDraftObject();
        TokenResponsePerIdentityRequest FindByAccessToken(string accessToken);
        TokenResponsePerIdentityRequest CreatNew();
        TokenResponsePerIdentityRequest FindLast(int userId, int clientId, bool needAccessToken = true, bool issuedByLocal = true);
    }
}
