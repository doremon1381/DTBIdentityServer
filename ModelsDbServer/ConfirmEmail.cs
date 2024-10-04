using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ServerDbModels
{
    [Table("ConfirmEmails")]
    [PrimaryKey(nameof(Id))]
    public class ConfirmEmail : DbModelBase
    {
#if IdentityServer
        [Required]
#endif
        public string ConfirmCode { get; set; } = string.Empty;
        public DateTime? ExpiryTime { get; set; } = null;
        public DateTime CreatedTime { get; set; } = DateTime.Now;
        public bool IsConfirmed { get; set; } = false;
        // TODO: use confirm code for changing password or ...
        public int Purpose { get; set; } = 0;

        public int? UserId { get; set; } = null;
#if IdentityServer
        public int? ClientId { get; set;} = null;
        public Client? Client { get; set; } = null;
        public UserIdentity? User { get; set; } = null;
#else
        public UserToken? User { get; set; }
#endif
    }

    public enum ConfirmEmailPurpose
    {
        None,
        CreateIdentity,
        ChangePassword
    }
}
