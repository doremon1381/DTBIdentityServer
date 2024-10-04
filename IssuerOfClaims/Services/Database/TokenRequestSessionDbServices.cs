using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class TokenRequestSessionDbServices : DbTableBase<TokenRequestSession>, ITokenRequestSessionDbServices
    {
        private DbSet<TokenRequestSession> _loginSession;
        //private DbTableServices<TokenRequestSession> _issuseTokenSession;

        public TokenRequestSessionDbServices(IConfigurationManager configuration) : base(configuration)
        {
            //_loginSession = this.dbModels;
        }

        public TokenRequestSession FindByAccessToken(string accessToken)
        {
            throw new NotImplementedException();
        }

        public TokenRequestSession CreateTokenRequestSession()
        {
            TokenRequestSession obj = new TokenRequestSession();

            using (var dbContext = CreateDbContext(configuration))
            {
                _loginSession = dbContext.GetDbSet<TokenRequestSession>();
                _loginSession.Add(obj);

                dbContext.SaveChanges();
            }

            return obj;
        }

        public TokenRequestSession FindById(int id)
        {
            TokenRequestSession obj;

            using (var dbContext = CreateDbContext(configuration))
            {
                _loginSession = dbContext.GetDbSet<TokenRequestSession>();
                obj = _loginSession.First(t => t.Id.Equals(id));

                //dbContext.SaveChanges();
            }

            ValidateEntity(obj);

            return obj;
        }

        //public bool Update(TokenRequestSession requestSession)
        //{
        //    return this.Update(requestSession);
        //}
    }

    //public abstract class DbTableServicesAbstract<T> where T : class, IDbTable
    //{
    //    private IConfigurationManager _configuration;
    //    protected DbTableServicesAbstract(IConfigurationManager configuration)
    //    {
    //        this._configuration = configuration;
    //        dbTableServices = new Lazy<DbTableServices<T>>(() => new DbTableServices<T>(configuration));
    //    }

    //    public Lazy<DbTableServices<T>> dbTableServices { get; private set; }
    //}

    //public class DbTableServices<T> : DbTableBase<T>, IDbContextBase<T> where T : class, IDbTable
    //{
    //    public DbTableServices(IConfigurationManager configuration) : base(configuration)
    //    {
    //    }
    //}

    //public interface IDbTableServices<T> : IDbContextBase<T> where T : class, IDbTable
    //{

    //}

    //public class QueryBuilder
    //{

    //}

    public interface ITokenRequestSessionDbServices : IDbContextBase<TokenRequestSession>
    {
        TokenRequestSession FindByAccessToken(string accessToken);
        TokenRequestSession CreateTokenRequestSession();
        TokenRequestSession FindById(int id);
        //bool Update(TokenRequestSession aCFProcessSession);
    }
}
