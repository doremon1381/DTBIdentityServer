using System.ComponentModel.DataAnnotations.Schema;

namespace ServerDbModels
{
    public class DbTableBase: IDbTable
    {
#if IdentityServer
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
#endif
        public int Id { get; set; }
    }
}
