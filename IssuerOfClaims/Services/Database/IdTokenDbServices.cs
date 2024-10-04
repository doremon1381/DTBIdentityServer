using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class IdTokenDbServices : DbTableBase<IdToken>, IIdTokenDbServices
    {
        private readonly DbSet<IdToken> _IdTokens;

        public IdTokenDbServices(IConfigurationManager configuration) : base(configuration)
        {
            //_IdTokens = this.dbModels;
        }

        public IdToken GetDraft()
        {
            return new IdToken();
        }
    }

    public interface IIdTokenDbServices: IDbContextBase<IdToken>
    {
        IdToken GetDraft();
    }
}
