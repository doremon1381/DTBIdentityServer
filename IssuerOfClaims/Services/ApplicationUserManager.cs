using IssuerOfClaims.Controllers.Ultility;
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
                .Include(u => u.ConfirmEmails)
                .Include(u => u.IdentityUserRoles)
                .Include(u => u.TokenRequestHandlers)
                .ThenInclude(l => l.TokenRequestSession).ThenInclude(s => s.Client).ToList());
        }

        public UserIdentity CreateUser(RegisterParameters parameters)
        {
            var newUser = new UserIdentity
            {
                UserName = parameters.UserName.Value,
                Email = parameters.Email.Value,
                FirstName = parameters.FirstName.Value,
                LastName = parameters.LastName.Value,
                FullName = string.Format("{0} {1}", parameters.LastName.Value, parameters.FirstName.Value),
                Gender = parameters.Gender.Value
            };

            Current.CreateAsync(newUser, parameters.Password.Value).Wait();

            return newUser;
        }

        public bool HasUser(string userName)
        {
            var user = this.Current.Users.ToHashSet().FirstOrDefault(u => u.UserName == userName);

            if (user == null)
                return false;
            return true;
        }
    }

    public interface IApplicationUserManager
    {
        UserManager<UserIdentity> Current { get; }
        List<UserIdentity> UserIdentities { get; }
        UserIdentity CreateUser(RegisterParameters parameters);
        bool HasUser(string userName);
    }
}
