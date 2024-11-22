using IssuerOfClaims.Models.Request.RequestParameter;
using Microsoft.AspNetCore.Http;
using ServerUltilities;
using ServerUltilities.Extensions;
using ServerUltilities.Identity;
using System.Net;
using static ServerUltilities.Identity.Constants;

namespace IssuerOfClaims.Models.Request.Factory
{
    public class RegisterParametersFactory : RequestParametersFactory<RegisterParameters>
    {
        public RegisterParametersFactory(string queryString) : base(queryString)
        {
        }

        public override RegisterParameters ExtractParametersFromQuery(IHeaderDictionary headers)
        {
            var obj = (RegisterParameters)Constructor.Invoke(null) ?? throw new CustomException("Exception message is not defined!");

            var usernamePassword = GetUsernameAndPasswordFromHeader(headers);

            SetUserName(obj, usernamePassword.UserName);
            SetPassword(obj, usernamePassword.Password);

            base.InitiateProperties(obj);

            return obj;
        }

        private (string UserName, string Password) GetUsernameAndPasswordFromHeader(IHeaderDictionary headers)
        {
            string? userCredential = headers[RegisterRequest.Register][0];

            ValidateHeader(userCredential);

            var userNamePassword = userCredential.Replace(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC, "").Trim().ToBase64Decode();

            // TODO: will need to validate username and password, from client and server
            string userName = userNamePassword.Split(":")[0];
            string password = userNamePassword.Split(":")[1];

            return new(userName, password);
        }

        private void SetUserName(RegisterParameters obj, string username)
        {
            var usernameP = PropertiesOfType.First(p => p.Name.Equals(nameof(RegisterRequest.UserName)));
            var parameter = new Parameter(RegisterRequest.UserName, OauthRequest);

            parameter.SetValue(username);
            usernameP.SetValue(obj, usernameP);

            PropertiesOfType.Remove(usernameP);
        }

        private void SetPassword(RegisterParameters obj, string password)
        {
            var passwordP = PropertiesOfType.First(p => p.Name.Equals(nameof(RegisterRequest.Password)));
            var parameter = new Parameter(RegisterRequest.Password, OauthRequest);

            parameter.SetValue(password);
            passwordP.SetValue(obj, parameter);

            PropertiesOfType.Remove(passwordP);
        }

        private static void ValidateHeader(string? userCredential)
        {
            if (string.IsNullOrEmpty(userCredential))
                throw new CustomException(ExceptionMessage.REGISTER_INFORMATION_NULL_OR_EMPTY, HttpStatusCode.BadRequest);
        }
    }
}
