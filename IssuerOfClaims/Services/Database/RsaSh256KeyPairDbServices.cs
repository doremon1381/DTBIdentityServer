using IssuerOfClaims.Database;
using ServerDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class RsaSh256KeyPairDbServices : DbTableBase<RsaSh256KeyPair>, IRsaSh256KeyPairDbServices
    {
        public RsaSh256KeyPairDbServices(IConfigurationManager configuration) : base(configuration)
        {
        }
    }

    public interface IRsaSh256KeyPairDbServices
    {
    }
}
