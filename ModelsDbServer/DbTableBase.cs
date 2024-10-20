using System.ComponentModel.DataAnnotations.Schema;

namespace ServerDbModels
{
    public class DbTableBase<TIdentityKeyType>: IDbTable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public TIdentityKeyType Id { get; set; }
    }
}
