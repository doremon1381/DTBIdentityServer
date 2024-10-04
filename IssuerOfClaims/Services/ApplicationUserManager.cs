using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ServerDbModels;

namespace IssuerOfClaims.Services
{
    public class ApplicationUserManager : UserManager<UserIdentity>, IApplicationUserManager
    {
        public UserManager<UserIdentity> Current { get; private set; }
        public List<UserIdentity> UserIdentities { get; private set; } = new List<UserIdentity>();
        public ApplicationUserManager(IUserStore<UserIdentity> store, IOptions<IdentityOptions> optionsAccessor, IPasswordHasher<UserIdentity> passwordHasher
            , IEnumerable<IUserValidator<UserIdentity>> userValidators, IEnumerable<IPasswordValidator<UserIdentity>> passwordValidators
            , ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, IServiceProvider services
            , ILogger<UserManager<UserIdentity>> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
            this.Current = new UserManager<UserIdentity>(store, optionsAccessor, passwordHasher, userValidators, passwordValidators
                , keyNormalizer, errors, services, logger);

            this.UserIdentities.AddRange(Current.Users
                .Include(u => u.IdToken)
                .Include(u => u.ConfirmEmails)
                .Include(u => u.IdentityUserRoles)
                .Include(u => u.TokenRequestHandlers)
                .ThenInclude(l => l.TokenRequestSession).ThenInclude(s => s.Client).ToList());
        }
    }

    public interface IApplicationUserManager
    {
        UserManager<UserIdentity> Current { get; }
        public List<UserIdentity> UserIdentities { get; }
    }
}
