using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class ConfirmEmailDbServices : DbTableBase<ConfirmEmail>, IConfirmEmailDbServices
    {
        public ConfirmEmailDbServices() 
        {
        }

        public ConfirmEmail GetDraft()
        {
            return new ConfirmEmail();
        }

        public ConfirmEmail GetByCode(string code)
        {
            ConfirmEmail obj = default;

            UsingDbSet((confirmEmails) =>
            {
                obj = confirmEmails
                .Include(c => c.User)
                .First(c => c.ConfirmCode == code);
            });

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
