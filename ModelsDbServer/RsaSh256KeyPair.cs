using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServerDbModels
{
    /// <summary>
    /// public key and private key pair for issuing idtoken
    /// </summary>
    [Table($"{nameof(RsaSh256KeyPair)}s")]
    [PrimaryKey(nameof(Id))]
    public class RsaSh256KeyPair: DbTableBase
    {
        public string Private { get; set; }
        public string Public { get; set; }

        public DateTime ExpiredAt { get; set; }

        //[ForeignKey(nameof(UserIdentityId))]
        //public int UserIdentityId { get; set; }
        //public UserIdentity UserIdentity { get; set; }
    }
}
