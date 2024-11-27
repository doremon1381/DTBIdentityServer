using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities.Extensions;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public class ConfirmEmailDbService : DbTableServicesBase<ConfirmEmail>, IConfirmEmailDbService
    {
        public ConfirmEmailDbService(IServiceProvider serviceProvider) : base(serviceProvider)
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
                .Where(c => c.ConfirmCode == code)
                .AsNoTracking()
                .First();
            });

            ValidateEntity(obj, HttpStatusCode.NotFound, $"{nameof(ConfirmEmailDbService)}: {ExceptionMessage.OBJECT_IS_NULL}");

            return obj;
        }
    }

    public interface IConfirmEmailDbService : IDbContextBase<ConfirmEmail>
    {
        //ConfirmEmail Get(int id);
        ConfirmEmail GetDraft();
        Task<ConfirmEmail> GetByCodeAsync(string code);
    }
}
