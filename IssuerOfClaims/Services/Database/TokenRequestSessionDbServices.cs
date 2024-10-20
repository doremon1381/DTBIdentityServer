using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public class TokenRequestSessionDbServices : DbTableServicesBase<IdentityRequestSession>, ITokenRequestSessionDbServices
    {
        public TokenRequestSessionDbServices() 
        {
        }

        public IdentityRequestSession FindByAccessToken(string accessToken)
        {
            throw new NotImplementedException();
        }

        public IdentityRequestSession CreateTokenRequestSession(IdentityRequestHandler requestHandler)
        {
            IdentityRequestSession obj = new IdentityRequestSession()
            {
                IdentityRequestHandlerId = requestHandler.Id
            };

            UsingDbSetWithSaveChanges(dbSet => 
            {
                dbSet.Add(obj);
            });

            return obj;
        }

        public IdentityRequestSession FindById(int id)
        {
            IdentityRequestSession obj = null;

            UsingDbSet(_loginSessions =>
            {
                obj = _loginSessions.First(t => t.Id.Equals(id));
            });

            ValidateEntity(obj, HttpStatusCode.NotFound);

            return obj;
        }

        //public bool Update(TokenRequestSession requestSession)
        //{
        //    return this.Update(requestSession);
        //}
    }

    public interface ITokenRequestSessionDbServices : IDbContextBase<IdentityRequestSession>
    {
        IdentityRequestSession FindByAccessToken(string accessToken);
        IdentityRequestSession CreateTokenRequestSession(IdentityRequestHandler requestHandler);
        IdentityRequestSession FindById(int id);
        //bool Update(TokenRequestSession aCFProcessSession);
    }
}
