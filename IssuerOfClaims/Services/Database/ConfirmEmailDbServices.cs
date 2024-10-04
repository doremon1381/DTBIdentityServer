using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class ConfirmEmailDbServices : DbTableBase<ConfirmEmail>, IConfirmEmailDbServices
    {
        private DbSet<ConfirmEmail> _ConfirmEmails { get; set; }

        public ConfirmEmailDbServices(IConfigurationManager configuration) : base(configuration)
        {
            //_ConfirmEmails = dbModels;
        }

        public ConfirmEmail GetDraft()
        {
            return new ConfirmEmail();
        }

        public ConfirmEmail GetByCode(string code)
        {
            ConfirmEmail obj;

            using (var dbContext = CreateDbContext(configuration))
            {
                obj = _ConfirmEmails
                .Include(c => c.User)
                .First(c => c.ConfirmCode == code);
            }

            ValidateEntity(obj, $"{this.GetType().Name}: ConfirmEmail is null!");

            return obj;
        }
    }

    public interface IConfirmEmailDbServices : IDbContextBase<ConfirmEmail>
    {
        //ConfirmEmail Get(int id);
        ConfirmEmail GetDraft();
        ConfirmEmail GetByCode(string code);
    }
}
