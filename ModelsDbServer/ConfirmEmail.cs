using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IssuerOfClaims.Models.DbModel
{
    [Table($"{nameof(ConfirmEmail)}s")]
    [PrimaryKey(nameof(Id))]
    public class ConfirmEmail : DbTableBase<Guid>
    {
        [Required]
        public string ConfirmCode { get; set; } = string.Empty;
        public DateTime? ExpiryTime { get; set; } = null;
        public DateTime CreatedTime { get; set; } = DateTime.Now;
        public bool IsConfirmed { get; set; } = false;
        // TODO: use confirm code for changing password or ...
        public string Purpose { get; set; } = ConfirmEmailPurpose.None;

        public Guid? UserId { get; set; } = null;
        public Guid? ClientId { get; set;} = null;
        public Client? Client { get; set; } = null;
        public UserIdentity? User { get; set; } = null;
    }

    public static class ConfirmEmailPurpose
    {
        public const string None = "none";
        public const string CreateIdentity = "create_identity";
        public const string ChangePassword = "change_password";
    }
}
