﻿using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IssuerOfClaims.Models.DbModel
{
    [Table($"UserIdentities")]
    [PrimaryKey(nameof(Id))]
    public class UserIdentity : IdentityUser<Guid>, IDbTable
    {
        [Required]
        public string? FullName { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Gender { get; set; }
        public DateTime? DateOfBirth { get; set; }
        public string? Avatar { get; set; }
        #region address https://openid.net/specs/openid-connect-implicit-1_0.html#AddressClaim
        [NotMapped]
        /// <summary>
        /// <para>Full mailing address, formatted for display or use on a mailing label. </para>
        /// <para>This field MAY contain multiple lines, separated by newlines. </para>
        /// Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
        /// </summary>
        public string? AddressFormatted { get; set; }
        /// <summary>
        /// Full street address component
        /// </summary>
        public string? Address { get; set; }
        public string? Locality { get; set; }
        public string? Region { get; set; }
        public string? PostalCode { get; set; }
        public string? Country { get; set; }
        #endregion
        public DateTime CreateTime { get; set; }
        public DateTime? UpdateTime { get; set; }
        public override bool EmailConfirmed { get; set; }
        /// <summary>
        /// TODO: by logic of current process of creation, always need UserName, so it basically not null
        ///     : but if allow identity from another source be used, so when user is created, UserName may not need
        /// </summary>
        public override string? UserName { get; set; }
        /// <summary>
        /// TODO: Will learn how to use it later
        /// </summary>
        public override string? SecurityStamp { get; set; } = null;

        /// <summary>
        /// By default, a client must have an user identity as it owner. 
        /// <para>Because it need an user to be created. I will add function to create client in the future.</para>
        /// </summary>
        public List<Client> Clients { get; set; }

        ///// <summary>
        ///// Created along with user, only change when update user's data
        ///// </summary>
        //public IdToken? IdToken { get; set; }
        public List<ConfirmEmail>? ConfirmEmails { get; set; }
        public List<IdentityUserRole> IdentityUserRoles { get; set; }
        public List<IdentityRequestHandler> IdentityRequestHandlers { get; set; }

        // TODO: temporary
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
            this.Avatar = "";
        }
    }
}
