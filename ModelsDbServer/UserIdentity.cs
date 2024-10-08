using Microsoft.AspNetCore.Identity;
using System;
#if IdentityServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace ServerDbModels
{
#if IdentityServer
    [Table("UserIdentities")]
    [PrimaryKey(nameof(Id))]
#endif
    public class UserIdentity : IdentityUser<int>, IDbTable
    {
#if IdentityServer
        [Required]
#endif
        public string? FullName { get; set; } = string.Empty;
        public string? FirstName { get; set; } = string.Empty;
        public string? LastName { get; set; } = string.Empty;
        public string? Gender { get; set; } = string.Empty;
        public DateTime? DateOfBirth { get; set; } = null;
        public string? Avatar { get; set; } = string.Empty;
        public bool IsEmailConfirmed { get; set; } = false;
        public DateTime CreateTime { get; set; } = DateTime.Now;
        public DateTime? UpdateTime { get; set; } = DateTime.Now;
#if IdentityServer
        [NotMapped]
#endif
        public override bool EmailConfirmed { get; set; }
        /// <summary>
        /// TODO: by logic of current process of creation, always need UserName, so it basically not null
        ///     : but if allow identity from another source be used, so when user is created, UserName may not need
        /// </summary>
        public override string? UserName { get; set; } = string.Empty;
        /// <summary>
        /// TODO: Will learn how to use it later
        /// </summary>
        public override string? SecurityStamp { get; set; } = null;
        ///// <summary>
        ///// Created along with user, only change when update user's data
        ///// </summary>
        //public IdToken? IdToken { get; set; }
        public List<ConfirmEmail>? ConfirmEmails { get; set; } = new List<ConfirmEmail>();
        public List<IdentityUserRole> IdentityUserRoles { get; set; } = new List<IdentityUserRole>();
        public List<TokenRequestHandler> TokenRequestHandlers { get; set; } = new List<TokenRequestHandler>();

        public UserIdentity()
        {
            this.AccessFailedCount = 0;
            this.PhoneNumber = string.Empty;
            this.PhoneNumberConfirmed = false;
            this.Email = string.Empty;
            this.LockoutEnabled = false;
            this.ConcurrencyStamp = string.Empty;
            this.LockoutEnd = null;
            this.NormalizedUserName = string.Empty;
            this.NormalizedEmail = string.Empty;
            this.SecurityStamp = string.Empty;
            this.TwoFactorEnabled = false;
        }
    }
}
