using System.ComponentModel.DataAnnotations.Schema;

namespace IssuerOfClaims.Models.DbModel
{
    public class DbTableBase<TIdentityKeyType>: IDbTable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public TIdentityKeyType Id { get; set; }
    }
}
