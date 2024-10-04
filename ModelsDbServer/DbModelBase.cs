using System.ComponentModel.DataAnnotations.Schema;

namespace ServerDbModels
{
    public class DbModelBase: IDbTable
    {
#if IdentityServer
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
#endif
        public int Id { get; set; }
    }
}
