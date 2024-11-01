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

        public async Task<UserIdentity> CreateUserAsync(RegisterParameters parameters)
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

            await Current.CreateAsync(newUser, parameters.Password.Value);

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

        public async Task<UserIdentity> GetOrCreateUserByEmailAsync(GoogleJsonWebSignature.Payload payload)
        {
            var user = this.Current.Users.FirstOrDefault(u => u.Email == payload.Email);

            if (user == null)
                user = await CreateUser(payload);

            return user;
        }

        private async Task<UserIdentity> CreateUser(GoogleJsonWebSignature.Payload payload)
        {
            var newUser = new UserIdentity
            {
                Email = payload.Email,
                FullName = payload.Name,
                EmailConfirmed = payload.EmailVerified,
                Avatar = payload.Picture
            };

            await Current.CreateAsync(newUser);

            return newUser;
        }
    }

    public interface IApplicationUserManager
    {
        UserManager<UserIdentity> Current { get; }
        Task<UserIdentity> CreateUserAsync(RegisterParameters parameters);
        bool EmailIsUsedForUser(string email);
        Task<UserIdentity> GetOrCreateUserByEmailAsync(GoogleJsonWebSignature.Payload payload);
        bool HasUser(string userName);
    }
}
