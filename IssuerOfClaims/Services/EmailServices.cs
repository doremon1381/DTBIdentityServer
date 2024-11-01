using IssuerOfClaims.Services.Database;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.WebUtilities;
using MimeKit;
using ServerDbModels;
using ServerUltilities;
using System.Text.Encodings.Web;
using System.Text;
using IssuerOfClaims.Models;
using ServerUltilities.Identity;
using IssuerOfClaims.Extensions;

namespace IssuerOfClaims.Services
{
    public class EmailServices : IEmailServices
    {
        private readonly IConfirmEmailDbServices _emailDbServices;
        private readonly IApplicationUserManager _applicationUserManager;
        private readonly MailSettings _mailSettings;

        public EmailServices(IConfirmEmailDbServices emailDbServices, IApplicationUserManager userManager, MailSettings mailSettings)
        {
            _emailDbServices = emailDbServices;
            _mailSettings = mailSettings;
            _applicationUserManager = userManager;
        }

        public async Task SendForgotPasswordCodeToEmailAsync(UserIdentity user, Guid clientId)
        {
            var code = await _applicationUserManager.Current.GeneratePasswordResetTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            int expiredTimeInMinutes = 2;
            await CreateConfirmEmailAsync(user.Id, clientId, code, ConfirmEmailPurpose.ChangePassword, expiredTimeInMinutes);

            string emailBody = $"Your password reset's security code is <span style=\"font-weight:bold; font-size:25px\">{code}</span>.";
            await SendMailAsync(user.UserName, user.Email, emailBody);
        }

        public async Task SendVerifyingEmailAsync(UserIdentity user, string callbackEndpoint, Guid clientId, string requestScheme, string requestHost)
        {
            var code = await _applicationUserManager.Current.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            int expiredTimeInMinutes = 60;
            await CreateConfirmEmailAsync(user.Id, clientId, code, ConfirmEmailPurpose.CreateIdentity, expiredTimeInMinutes);

            string callbackUrl = CreateCallbackUrl(requestScheme, requestHost, callbackEndpoint, user.Id, code);
            string emailBody = CreateEmailBody(callbackUrl);

            await SendMailAsync(user.UserName, user.Email, emailBody);
        }

        public async Task<ConfirmEmail> GetChangePasswordEmailByCodeAsync(string code)
        {
            var changePasswordEmail = await _emailDbServices.GetByCodeAsync(code);

            if (!changePasswordEmail.Purpose.Equals(ConfirmEmailPurpose.ChangePassword))
                throw new InvalidOperationException(ExceptionMessage.CONFIRM_EMAIL_SEEM_WRONG);
            if (!changePasswordEmail.ExpiryTime.HasValue || changePasswordEmail.ExpiryTime < DateTime.Now)
                throw new InvalidOperationException(ExceptionMessage.CONFIRM_EMAIL_EXPIRED);

            return changePasswordEmail;
        }

        public bool UpdateConfirmEmail(ConfirmEmail emailForChangingPassword)
        {
            return _emailDbServices.Update(emailForChangingPassword);
        }

        private static string CreateEmailBody(string callbackUrl)
        {
            var body = $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.";

            return body;
        }

        private static string CreateCallbackUrl(string requestScheme, string requestHost, string callbackEndpoint, Guid userId, string code)
        {
            string callbackUrl = string.Format("{0}?area=Identity&userId={1}&code={2}",
                   $"{requestScheme}://{requestHost}/auth/{callbackEndpoint}",
                   userId,
                   code);

            return callbackUrl;
        }

        private void SendEmail(string userName, string emailAddress, string emailBody)
        {
            var email = new MimeMessage();
            email.From.Add(new MailboxAddress(_mailSettings.Name, _mailSettings.EmailId));
            // TODO: test email for now
            email.To.Add(new MailboxAddress(userName, emailAddress));

            email.Subject = "Testing out email sending";
            // $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");
            email.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                //Text = $"<b>Hello all the way from the land of C# {callbackUrl}</b>"
                Text = emailBody
            };

            using (var smtp = new SmtpClient())
            {
                smtp.Connect(_mailSettings.Host, 587, false);

                // Note: only needed if the SMTP server requires authentication
                smtp.Authenticate(_mailSettings.EmailId, _mailSettings.Password);

                smtp.Send(email);
                smtp.Disconnect(true);
            }
        }

        private void CreateConfirmEmail(Guid userId, string code, Guid clientId, string purpose, int expiredTimeInMinutes)
        {
            try
            {
                var nw = _emailDbServices.GetDraft();
                nw.ConfirmCode = code;
                nw.Purpose = purpose;
                nw.IsConfirmed = false;
                nw.ExpiryTime = DateTime.Now.AddMinutes(expiredTimeInMinutes);
                nw.CreatedTime = DateTime.Now;

                if (_emailDbServices.Create(nw))
                {
                    nw.UserId = userId;
                    nw.ClientId = clientId;

                    _emailDbServices.Update(nw);
                }

            }
            catch (Exception)
            {
                throw;
            }
        }

        private async Task CreateConfirmEmailAsync(Guid userId, Guid clientId, string code, string purpose, int expiredTimeInMinutes)
        {
            await Task.Factory.StartNew(() => CreateConfirmEmail(userId, code, clientId, purpose, expiredTimeInMinutes), TaskCreationOptions.AttachedToParent);
        }

        private async Task SendMailAsync(string userName, string email, string emailBody)
        {
            await Task.Factory.StartNew(() => SendEmail(userName, email, emailBody), TaskCreationOptions.AttachedToParent);
        }
    }

    public interface IEmailServices
    {
        Task SendForgotPasswordCodeToEmailAsync(UserIdentity user, Guid clientId);
        Task SendVerifyingEmailAsync(UserIdentity user, string callbackEndpoint, Guid clientId, string requestScheme, string requestHost);
        Task<ConfirmEmail> GetChangePasswordEmailByCodeAsync(string code);
        bool UpdateConfirmEmail(ConfirmEmail emailForChangingPassword);
    }
}
