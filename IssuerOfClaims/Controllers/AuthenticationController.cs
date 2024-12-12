using IssuerOfClaims.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IssuerOfClaims.Models.DbModel;
using System.Net;
using IssuerOfClaims.Services.Database;
using IssuerOfClaims.Services;
using IssuerOfClaims.Services.Token;
using Microsoft.EntityFrameworkCore;
using ServerUltilities.Extensions;
using IssuerOfClaims.Controllers.Attributes;
using ServerUltilities;
using IssuerOfClaims.Models.Request.Factory;
using IssuerOfClaims.Models.Request.RequestParameter;

namespace IssuerOfClaims.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [ControllerName("auth")]
    public class AuthenticationController : ControllerBase
    {
        private readonly IClientDbService _clientDbServices;
        private readonly IApplicationUserManager _applicationUserManager;
        private readonly ITokenService _tokenManager;
        private readonly IEmailService _emailServices;

        public AuthenticationController(IClientDbService clientDbServices
            , IApplicationUserManager applicationUserManager
            , ITokenService tokenManager
            , IEmailService emailServices)
        {
            _clientDbServices = clientDbServices;
            _applicationUserManager = applicationUserManager;
            _tokenManager = tokenManager;
            _emailServices = emailServices;
        }

        #region Login
        [HttpPost("signin")]
        [Authorize]
        public async Task<ActionResult> SignIn_Post()
        {
            // Get user
            var principal = HttpContext.User;
            var user = await _applicationUserManager.Current.GetUserAsync(principal) 
                ?? throw new CustomException(ExceptionMessage.USER_NULL);

            var body = await Utilities.SerializeFormAsync(HttpContext.Request.Body);
            var query = body.Remove(0,1).Replace("path=","").ToBase64Decode().Split("&");
            var clientId = query.First(q => q.StartsWith("client_id")).Replace("client_id=","");

            // TODO: verify client
            var client = await _clientDbServices.FindAsync(clientId);

            // TODO: need to change to apply jwt token PoP, for now, I just create an encrypt jwt token using asymmetrickey and ignore rfc7800 specs
            //     : more information: https://datatracker.ietf.org/doc/html/rfc7800
            var idToken = await _tokenManager.GenerateIdTokenAsync(user, "openid", string.Empty, client.ClientId);

            // TODO: for test
            return Ok(idToken);
        }

        [HttpGet("signin")]
        [Authorize]
        public ActionResult SignIn_Get()
        {
            // Get user
            // gather request information, redirect to prompt view if it's need
            // TODO: for test
            return Ok(new { Prompt = "consent" });
        }

        [HttpPost("signin/callback")]
        [Authorize]
        public ActionResult SignInCallback()
        {
            return Ok();
        }
        #endregion

        #region resiger user
        // TODO: by default, I seperate the need of creating identity of someone with the flow of oauth2's authorization code flow 
        //     : but following specs, my implement maybe wrong, but I know it is optional or "more guideline" than "actual rules"
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<ActionResult> RegisterIdentity()
        {
#pragma warning disable CS8604 // Possible null reference argument.
            var parameters = new RegisterParametersFactory(HttpContext.Request.QueryString.Value)
                .ExtractParametersFromQuery(HttpContext.Request.Headers);
#pragma warning restore CS8604 // Possible null reference argument.

            return await RegisterUserAsync(parameters);
        }

        public async Task<ActionResult> RegisterUserAsync(RegisterParameters parameters)
        {
            // TODO: will add role later
            // TODO: for now, I allow one email can be used by more than one UserIdentity
            //     : but will change to "one email belong to one useridentity" later
            VerifyRegisterParameters(parameters.UserName.Value, parameters.Email.Value);

            // TODO: will check again
            var user = await _applicationUserManager.CreateUserAsync(parameters);

            // TODO: https://openid.net/specs/openid-connect-prompt-create-1_0.html#name-authorization-request
            Client? client = parameters.ClientId.Value != "" 
                ?  await _clientDbServices.FindAsync(parameters.ClientId.Value) 
                : null;

            // TODO: will check again
            string id_token = await _tokenManager.GenerateIdTokenAsync(user, string.Empty, parameters.Nonce.Value, client != null ? client.ClientId : "");

            if (parameters.Email.HasValue)
                await _emailServices.SendVerifyingEmailAsync(user, "confirmEmail", client != null ?  client.Id : null, Request.Scheme, Request.Host.ToString());

            object responseBody = CreateRegisterUserResponseBody(id_token, parameters.State.Value, parameters.State.HasValue);

            return StatusCode((int)HttpStatusCode.OK, responseBody);
        }

        private void VerifyRegisterParameters(string userName, string email)
        {
            if (_applicationUserManager.EmailIsUsedForUser(email)
                || _applicationUserManager.HasUser(userName))
                throw new CustomException(ExceptionMessage.USER_ALREADY_EXISTS, HttpStatusCode.BadRequest);
        }

        private static object CreateRegisterUserResponseBody(string id_token, string state = "", bool stateHasValue = false)
        {
            object responseBody = new
            {
                status = 200,
                message = "new user is created!",
                id_token
            };

            if (stateHasValue)
            {
                responseBody = new
                {
                    status = 200,
                    message = "new user is created!",
                    state,
                    id_token
                };
            }

            return responseBody;
        }
        #endregion

        #region confirm email after creating user
        /// <summary>
        /// TODO: will verify this function later
        /// </summary>
        /// <returns></returns>
        [HttpGet("confirmEmail")]
        [AllowAnonymous]
        public async Task<ActionResult> CreatingUserConfirmAsync()
        {
            if (!HttpContext.Request.QueryString.HasValue)
                return StatusCode((int)HttpStatusCode.BadRequest, ExceptionMessage.QUERYSTRING_NOT_NULL_OR_EMPTY);

            var query = HttpContext.Request.Query;
            var userId = Guid.Parse(query["userId"]);
            var code = query["code"];

            // TODO:
            var user = _applicationUserManager.Current.Users.Include(u => u.ConfirmEmails).FirstOrDefault(u => u.Id == userId);
            var confirmEmail = user.ConfirmEmails.First(e => e.Purpose == ConfirmEmailPurpose.CreateIdentity);

            if (confirmEmail.IsConfirmed == true)
                return Ok(ResponseUtilities.ResponseMessages[DefaultResponseMessage.EmailIsConfirmed].Value);

            if (ValidateConfirmEmail(confirmEmail.ConfirmCode, confirmEmail.ExpiryTime.Value, code))
            {
                user.EmailConfirmed = true;
                confirmEmail.IsConfirmed = true;
            }

            await _applicationUserManager.Current.UpdateAsync(user);

            return Ok(ResponseUtilities.ResponseMessages[DefaultResponseMessage.EmailIsConfirmed].Value);
        }

        private static bool ValidateConfirmEmail(string emailConfirmCode, DateTime emailExpiredTime, string code)
        {
            if (!emailConfirmCode.Equals(code))
                throw new CustomException(ExceptionMessage.EMAIL_CONFIRM_CODE_NOT_MATCH, HttpStatusCode.NotFound);
            if (!(emailExpiredTime > DateTime.Now))
                throw new CustomException(ExceptionMessage.EMAIL_IS_EXPIRED, HttpStatusCode.BadRequest);

            return true;
        }
        #endregion

        #region update user
        [HttpPost("user/update")]
        [Authorize]
        // TODO: will update later
        public async Task<ActionResult> UpdateUserAsync()
        {
            var userClaims = HttpContext.User;

            var user = await _applicationUserManager.Current.GetUserAsync(userClaims);

            // TODO: will check again
            if (user == null)
                return StatusCode(500, ExceptionMessage.UNKNOW_ERROR);
            if (user.EmailConfirmed == true)
                return StatusCode(400, ExceptionMessage.EMAIL_IS_MISSING);

            //return await SendVerifyingEmailAsync(user, "updateUser", client);
            return Ok();
        }
        #endregion

        #region forget password
        [HttpPost("user/forgotPassword")]
        [AllowAnonymous]
        public async Task<ActionResult> ChangePasswordAfterEmailConfirm()
        {
            string requestBody = await Utilities.SerializeFormAsync(HttpContext.Request.Body);
            var parameters = new ChangePasswordParametersFactory(requestBody)
                .ExtractParametersFromQuery();

            // TODO: need to vefify client from request
            var client = _clientDbServices.FindAsync(parameters.ClientId.Value);

            var emailForChangingPassword = await _emailServices.GetChangePasswordEmailByCodeAsync(parameters.Code.Value);
            var user = emailForChangingPassword.User ?? throw new CustomException(ExceptionMessage.USER_NULL);

            // TODO: will check again
            await _applicationUserManager.Current.RemovePasswordAsync(user);
            await _applicationUserManager.Current.AddPasswordAsync(user, parameters.NewPassword.Value);
            emailForChangingPassword.IsConfirmed = true;

            _emailServices.UpdateConfirmEmail(emailForChangingPassword);

            return Ok();
        }

        [HttpGet("user/forgotPassword")]
        [AllowAnonymous]
        public async Task<ActionResult> ForgotPassword()
        {
            var queryString = HttpContext.Request.QueryString.Value;
            var query = new ForgotPasswordParametersFactory(queryString)
                .ExtractParametersFromQuery();

            string clientId = query.ClientId.Value;
            string email = query.Email.Value;

            var client = await _clientDbServices.FindAsync(clientId);
            if (client == null)
                return StatusCode((int)HttpStatusCode.BadRequest, ExceptionMessage.CLIENTID_NOT_FOUND);

            // TODO: get user by email, by logic, username + email is unique for an user that is stored in db, but fow now, email may be duplicated for test
            var user = _applicationUserManager.Current.Users.FirstOrDefault(u => u.Email.Equals(email));
            await _emailServices.SendForgotPasswordCodeToEmailAsync(user, client.Id);

            return Ok();
        }
        #endregion

        //private static string uri = $"https://accounts.google.com" +
        //    $"/signin/oauth/id?authuser=0" +
        //    $"&part=AJi8hAMFcTSTm-vGntjaPjAnglUow3ADiAG5hk0yX_kjA9HFrtvs0emFQwWExy-p9QUFy5xNCs7AOCbBuGwGVUanuLtxHq8IoupkK8nSbT-lKzKrEnFZj0gxblh2RfcLdP-8c44o44x6lXGMtH6Mq7_IsftyaKEH9yxd7wHYsrKdwWVKE899tqOh2vaihJMgzdF4j2ROpnAMZvd1VwirWHUdx5AgsdUMh0YhzCHtkvfL6I3jmG4Z-LkxtpztBOhRqz7-Dv9x6546cTH0NbZZY860EEVyNfG7rZ2ruZu9FbP3eGHnPe43g7MqytMUDm1rlnQmzttg5qMJ-w-JDbdt2GX-P45t6a1XGK7-7XpCJKDYlw7MICmIBdTGe7zJ1sisEfgq8khxnIznXxyri8h0fm6y8Ug1CMcxqhuUvSdQiinEhpe8GHQaeyDKq6WjQj15QPWvlXGFD0veRbVWnt5q2Z-9-CQ0GMWldNmjnmh_KOfYYG0G_ghTUCTp3exCrljyJKNI0wG-GStrX8-yRAKzecj62anGbSzLwRW0-b1w6XzEwNngJ-AHu8-OjQa1Tgadb_L_fsBS6DLfCEWLT70whFQZ3YpkRPCOPsiQWCnfP0b7F8oAvIU-rQaz0GrppgUFQGQh6xbJcZ0r2Y-M55m_shl6XeSys_byR2zCudtlh9WSUpPeUHeUux9p82XN2Xsp6BrxhMxLjzKu0ssfXyk3MAgbB_FFrkfAYzvxAF4nnYjp66jneSWrlMBVdGAAEuLPmihKnBIZUtwqPHZ9erVaMhLCcJAlt1DxQdnB2C_r8SYTCSSUWA36yPmlpLZ6imM06jClpePfz-NNluEL6wx2ywdsuXYjPcBTMGh-nN4Tdl5kXWTvodavsxHLOXgL1Qmrtzy_gQBgifDD5gJGpIhXnS5vlXlCh6gJSBHHalmKyukcpY8FO3p-Oy04DYlHg_OQNwUjuNUvxWnKNbvbsPdi5DXE2bBmhECqeVNgUO_haHVjHXjNff_TSRLWJ_zZBW9fuHqrdk6N44y1FvtDP37XKgZCu4pemvib8GXXkyA_OiTI-_dLH-1WvMyncNEM9vlbMEpOGGboWDHraOkayPP93KX83FoIQCV8cz4tTPLDr1HYUyhGZg9DgWE" +
        //    $"&flowName=GeneralOAuthFlow" +
        //    $"&as=S1628637618%3A1729242776212909" +
        //    $"&client_id=558160357396-q5qp0ppf4r5svc0g0smshfs8cdcffkm3.apps.googleusercontent.com" +
        //    $"&rapt=AEjHL4O502QfcCv_pu9T9F86MMsGDDCljsTDHQcL4K-4pZjNVSNN1gi9YrknjsXGiP12As2LwyIwHMiTsi9ad7GssMoIMmqrZw#";
    }
}
