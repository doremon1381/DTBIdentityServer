using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class TokenRequestSessionDbServices : DbTableBase<TokenRequestSession>, ITokenRequestSessionDbServices
    {
        public TokenRequestSessionDbServices() 
        {
        }

        public TokenRequestSession FindByAccessToken(string accessToken)
        {
            throw new NotImplementedException();
        }

        public TokenRequestSession CreateTokenRequestSession()
        {
            TokenRequestSession obj = new TokenRequestSession();

            UsingDbSetWithSaveChanges(dbSet => 
            {
                dbSet.Add(obj);
            });

            return obj;
        }

        public TokenRequestSession FindById(int id)
        {
            TokenRequestSession obj = null;

            UsingDbSet(_loginSessions =>
            {
                obj = _loginSessions.First(t => t.Id.Equals(id));
            });

            ValidateEntity(obj);

            return obj;
        }

        //public bool Update(TokenRequestSession requestSession)
        //{
        //    return this.Update(requestSession);
        //}
    }

    public interface ITokenRequestSessionDbServices : IDbContextBase<TokenRequestSession>
    {
        TokenRequestSession FindByAccessToken(string accessToken);
        TokenRequestSession CreateTokenRequestSession();
        TokenRequestSession FindById(int id);
        //bool Update(TokenRequestSession aCFProcessSession);
    }
}
