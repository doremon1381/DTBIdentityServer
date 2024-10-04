using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServerDbModels
{
    [Table($"{nameof(IdToken)}s")]
    [PrimaryKey(nameof(Id))]
    public class IdToken: DbModelBase
    {
        public string Token { get; set; } = string.Empty;
        public DateTime? CreateTime { get; set; }

        public int UserId { get; set; }
        public UserIdentity User { get; set; }
    }
}
