using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities.Extensions;
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

        public async Task<ConfirmEmail> GetByCodeAsync(string code)
        {
            ConfirmEmail obj = default;

            await UsingDbSetAsync((confirmEmails) =>
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
        Task<ConfirmEmail> GetByCodeAsync(string code);
    }
}
