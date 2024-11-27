using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Models.DbModel;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public class IdentityRequestSessionDbService : DbTableServicesBase<IdentityRequestSession>, IIdentityRequestSessionDbService
    {
        public IdentityRequestSessionDbService(IServiceProvider serviceProvider) : base(serviceProvider) 
        {
        }

        public IdentityRequestSession FindByAccessToken(string accessToken)
        {
            throw new NotImplementedException();
        }

        public IdentityRequestSession CreateTokenRequestSession(Guid requestHandlerId)
        {
            IdentityRequestSession obj = new IdentityRequestSession()
            {
                IdentityRequestHandlerId = requestHandlerId
            };

            UsingDbSetWithSaveChanges(dbSet => 
            {
                dbSet.Add(obj);
            });

            return obj;
        }

        public async Task<IdentityRequestSession> FindByIdAsync(int id)
        {
            IdentityRequestSession obj = null;

            await UsingDbSetAsync(_loginSessions =>
            {
                obj = _loginSessions
                    .Where(t => t.Id.Equals(id))
                    .AsNoTracking()
                    .First();
            });

            ValidateEntity(obj, HttpStatusCode.NotFound);

            return obj;
        }

        public IdentityRequestSession GetDraft()
        {
            IdentityRequestSession obj = new IdentityRequestSession();
            return obj;
        }

        //public bool Update(TokenRequestSession requestSession)
        //{
        //    return this.Update(requestSession);
        //}
    }

    public interface IIdentityRequestSessionDbService : IDbContextBase<IdentityRequestSession>
    {
        IdentityRequestSession FindByAccessToken(string accessToken);
        IdentityRequestSession CreateTokenRequestSession(Guid requestHandlerId);
        Task<IdentityRequestSession> FindByIdAsync(int id);
        IdentityRequestSession GetDraft();
        //bool Update(TokenRequestSession aCFProcessSession);
    }
}
