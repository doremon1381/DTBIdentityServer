using IssuerOfClaims.Database;
using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public class ConfirmEmailDbServices : DbTableServicesBase<ConfirmEmail>, IConfirmEmailDbServices
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

            ValidateEntity(obj, HttpStatusCode.NotFound, $"{nameof(ConfirmEmailDbServices)}: {ExceptionMessage.OBJECT_IS_NULL}");

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
