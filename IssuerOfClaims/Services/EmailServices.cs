using IssuerOfClaims.Services.Database;
using Microsoft.AspNetCore.Mvc;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.WebUtilities;
using MimeKit;
using ServerDbModels;
using ServerUltilities;
using System.Text.Encodings.Web;
using System.Text;

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

        public async Task SendForgotPasswordCodeToEmailAsync(UserIdentity user, Client client)
        {
            var code = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(8);
            //var sr = _userManager.get
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            int expiredTimeInMinutes = 1;
            await CreateConfirmEmailAsync(user, code, client, ConfirmEmailPurpose.ChangePassword, expiredTimeInMinutes);

            string emailBody = $"Your password reset's security code is <span style=\"font-weight:bold; font-size:25px\">{code}</span>.";
            SendEmail(user.UserName, user.Email, emailBody);
        }

        public async Task SendVerifyingEmailAsync(UserIdentity user, string callbackEndpoint, Client client, string requestScheme, string requestHost)
        {
            var code = await _applicationUserManager.Current.GenerateEmailConfirmationTokenAsync(user);
            //var sr = _userManager.get
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            int expiredTimeInMinutes = 60;
            await CreateConfirmEmailAsync(user, code, client, ConfirmEmailPurpose.CreateIdentity, expiredTimeInMinutes);

            string callbackUrl = string.Format("{0}?area=Identity&userId={1}&code={2}",
                   $"{requestScheme}://{requestHost}/oauth2/{callbackEndpoint}",
                   user.Id,
                   code);
            string emailBody = $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.";

            SendEmail(user.UserName, user.Email, emailBody);
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

        private async Task CreateConfirmEmailAsync(UserIdentity user, string code, Client client, ConfirmEmailPurpose purpose, int expiredTimeInMinutes)
        {
            try
            {
                var nw = _emailDbServices.GetDraft();
                nw.ConfirmCode = code;
                nw.Purpose = (int)purpose;
                nw.IsConfirmed = false;
                nw.ExpiryTime = DateTime.Now.AddMinutes(expiredTimeInMinutes);
                nw.CreatedTime = DateTime.Now;

                if (_emailDbServices.Create(nw))
                {
                    nw.User = user;
                    nw.Client = client;

                    _emailDbServices.Update(nw);
                }

            }
            catch (Exception)
            {
                throw;
            }
        }

        public ConfirmEmail GetChangePasswordEmailByCode(string code)
        {
            var changePasswordEmail = _emailDbServices.GetByCode(code);

            if (!changePasswordEmail.Purpose.Equals((int)ConfirmEmailPurpose.ChangePassword))
                throw new InvalidOperationException("something inside this process is wrong!");
            if (!changePasswordEmail.ExpiryTime.HasValue || changePasswordEmail.ExpiryTime < DateTime.Now)
                throw new InvalidOperationException("error with email's expired time!");

            return changePasswordEmail;
        }

        public bool UpdateConfirmEmail(ConfirmEmail emailForChangingPassword)
        {
            return _emailDbServices.Update(emailForChangingPassword);
        }
    }

    public interface IEmailServices
    {
        Task SendForgotPasswordCodeToEmailAsync(UserIdentity user, Client client);
        Task SendVerifyingEmailAsync(UserIdentity user, string callbackEndpoint, Client client, string requestScheme, string requestHost);
        ConfirmEmail GetChangePasswordEmailByCode(string code);
        bool UpdateConfirmEmail(ConfirmEmail emailForChangingPassword);
    }
}
