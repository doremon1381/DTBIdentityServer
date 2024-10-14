using Google.Apis.Auth;
using IssuerOfClaims.Extensions;
using IssuerOfClaims.Models;
using IssuerOfClaims.Models.Request;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ServerDbModels;
using System.Net;

namespace IssuerOfClaims.Services
{
    public class ApplicationUserManager : UserManager<UserIdentity>, IApplicationUserManager
    {
        public UserManager<UserIdentity> Current { get; private set; }
        public ApplicationUserManager(IUserStore<UserIdentity> store, IOptions<IdentityOptions> optionsAccessor, IPasswordHasher<UserIdentity> passwordHasher
            , IEnumerable<IUserValidator<UserIdentity>> userValidators, IEnumerable<IPasswordValidator<UserIdentity>> passwordValidators
            , ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, IServiceProvider services
            , ILogger<UserManager<UserIdentity>> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
            this.Current = new UserManager<UserIdentity>(store, optionsAccessor, passwordHasher, userValidators, passwordValidators
                , keyNormalizer, errors, services, logger);
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
            var user = this.Current.Users.FirstOrDefault(u => u.UserName == userName);

            if (user == null)
                return false;
            return true;
        }

        public bool EmailIsUsedForUser(string email)
        {
            var user = this.Current.Users.FirstOrDefault(u => u.Email == email);

            if (user == null)
                return false;
            return true;
        }

        public UserIdentity GetOrCreateUserByEmail(GoogleJsonWebSignature.Payload payload)
        {
            var user = this.Current.Users.FirstOrDefault(u => u.Email == payload.Email);

            if (user == null)
                user = CreateUser(payload);

            return user;
        }

        private UserIdentity CreateUser(GoogleJsonWebSignature.Payload payload)
        {
            var newUser = new UserIdentity
            {
                //UserName = payload.UserName,
                Email = payload.Email,
                //FirstName = parameters.FirstName.Value,
                //LastName = parameters.LastName.Value,
                FullName = payload.Name,
                EmailConfirmed = payload.EmailVerified,
                Avatar = payload.Picture
                //Gender = payload.
            };

            Current.CreateAsync(newUser).Wait();

            return newUser;
        }
    }

    public interface IApplicationUserManager
    {
        UserManager<UserIdentity> Current { get; }
        UserIdentity CreateUser(RegisterParameters parameters);
        bool EmailIsUsedForUser(string email);
        //UserIdentity GetOrCreateUserByEmail(string email);
        UserIdentity GetOrCreateUserByEmail(GoogleJsonWebSignature.Payload payload);
        bool HasUser(string userName);
    }
}
