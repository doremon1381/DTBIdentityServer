using System.Text.Encodings.Web;
using System.Text;
using ServerUltilities.Identity;
using static ServerUltilities.Identity.OidcConstants;
using System.Net;
using static ServerUltilities.Identity.IdentityServerConstants;
using System.Text.Json;
using System.Web;
using IssuerOfClaims.Models.Request.RequestParameter;
using ServerUltilities;
using ServerUltilities.Extensions;

namespace IssuerOfClaims.Extensions
{
    public static class ResponseUtilities
    {
        #region for implicit grant request
        /// <summary>
        /// From identityserver4
        /// </summary>
        private static readonly string FormPostHtml = "<html><head><meta http-equiv='X-UA-Compatible' content='IE=edge' /><base target='_self'/></head><body><form method='post' action='{uri}'>{body}<noscript><button>Click to continue</button></noscript></form><script>window.addEventListener('load', function(){document.forms[0].submit();});</script></body></html>";

        public static async Task<string> IGF_CreateResponse(AuthCodeParameters parameters, string idToken, string accessToken, int secondsForTokenExpired)
        {
            return parameters.ResponseMode.Value switch
            {
                ResponseModes.FormPost => await Task.Run(() => ResponseUtilities.GetFormPostHtml(parameters.RedirectUri.Value, new Dictionary<string, string>()
                {
                    { AuthorizeResponse.AccessToken, accessToken },
                    { AuthorizeResponse.TokenType, OidcConstants.TokenResponse.BearerTokenType },
                    { AuthorizeResponse.IdentityToken, idToken },
                    { AuthorizeResponse.State, parameters.State.Value }
                })),
                ResponseModes.Query => await Task.Run(() => IGF_CreateResponseBody(accessToken, OidcConstants.TokenResponse.BearerTokenType, parameters.State.Value, idToken, secondsForTokenExpired, parameters.ResponseMode.Value, parameters.RedirectUri.Value)),
                ResponseModes.Fragment => await Task.Run(() => IGF_CreateResponseBody(accessToken, OidcConstants.TokenResponse.BearerTokenType, parameters.State.Value, idToken, secondsForTokenExpired, parameters.ResponseMode.Value, parameters.RedirectUri.Value)),
                _ => throw new CustomException(ExceptionMessage.NOT_IMPLEMENTED, HttpStatusCode.NotImplemented)
            };
        }

        private static string IGF_CreateResponseBody(string accessToken, string bearerTokenType, string state, string idToken, int expiredIn, string responseMode, string redirectUri)
        {
            string seprate = GetSeparatorByResponseMode(responseMode);

            StringBuilder builder = new StringBuilder($"{redirectUri}{seprate}{AuthorizeResponse.AccessToken}={accessToken}");
            builder.Append($"&{AuthorizeResponse.TokenType}={bearerTokenType}");
            builder.Append($"&{AuthorizeResponse.ExpiresIn}={expiredIn}");
            builder.Append($"&{AuthorizeResponse.IdentityToken}={idToken}");
            builder.Append(string.IsNullOrEmpty(state) ? "" : $"&{AuthorizeResponse.State}={state}");

            return builder.ToString();
        }

        private static string GetSeparatorByResponseMode(string responseMode)
        {
            return responseMode switch
            {
                ResponseModes.Query => "?",
                ResponseModes.Fragment => "#",
                _ => throw new CustomException(ExceptionMessage.RESPONSE_MODE_NOT_ALLOWED)
            };
        }

        /// <summary>
        /// From identityserver4
        /// </summary>
        /// <param name="redirectUri"></param>
        /// <param name="inputBody"></param>
        /// <returns></returns>
        private static string GetFormPostHtml(string redirectUri, Dictionary<string, string> inputBody)
        {
            var html = FormPostHtml;

            var url = redirectUri;
            url = HtmlEncoder.Default.Encode(url);
            html = html.Replace("{uri}", url);
            html = html.Replace("{body}", ToFormPost(inputBody));

            return html;
        }

        private static string ToFormPost(Dictionary<string, string> collection)
        {
            var builder = new StringBuilder(128);
            const string inputFieldFormat = "<input type='hidden' name='{0}' value='{1}' />\n";

            foreach (var keyValue in collection)
            {
                var value = keyValue.Value;
                //var value = value;
                value = HtmlEncoder.Default.Encode(value);
                builder.AppendFormat(inputFieldFormat, keyValue.Key, value);
            }

            return builder.ToString();
        }
        #endregion

        #region for authorization code request
        public static string ACF_I_CreateRedirectContent(string redirectUri, string responseMode, string state, string authorizationCode, string scope, string prompt)
        {
            string seprate = GetSeparatorByResponseMode(responseMode);

            StringBuilder builder = new StringBuilder($"{redirectUri}{seprate}code={authorizationCode}");
            builder.Append(string.IsNullOrEmpty(state) ? "" : $"&state={state}");
            builder.Append($"&scope={Uri.EscapeDataString(scope)}");
            builder.Append($"&prompt={prompt}");

            return builder.ToString();
        }
        #endregion

        #region for token request, response as json
        /// <summary>
        /// To achieve optimal performance, write JSON payloads that are already encoded as UTF-8 text rather than as UTF-16 strings. 
        /// <para> Use JsonEncodedText to cache and pre-encode known property names and values as statics.</para>
        /// <para> Powered by Copilot </para>
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="idToken"></param>
        /// <param name="expiredTimeSeconds"></param>
        /// <param name="refreshToken"></param>
        public static async Task<string> CreateTokenResponseStringAsync(string accessToken, string idToken, DateTime expiredInDateTime, string refreshToken = "", string tokenType = TokenResponse.BearerTokenType)
        {
            var valuePairs = await Task.Run(() => ConvertResponseStringToUTF8(accessToken, idToken, refreshToken, expiredInDateTime, tokenType));
            var json = await CreateTokenJsonStringAsync(valuePairs);

            return json;
        }

        private static TokenResponseValuePairs ConvertResponseStringToUTF8(string accessToken, string idToken, string refreshToken, DateTime expiredTime, string tokenType)
        {
            var accessTokenPair =
            new KeyValuePair<JsonEncodedText, JsonEncodedText>(
                JsonEncodedText.Encode(AuthorizeResponse.AccessToken),
                JsonEncodedText.Encode(accessToken)
            );
            var idTokenPair =
            new KeyValuePair<JsonEncodedText, JsonEncodedText>(
                JsonEncodedText.Encode(AuthorizeResponse.IdentityToken),
                JsonEncodedText.Encode(idToken)
            );
            var refreshTokenPair =
            new KeyValuePair<JsonEncodedText, JsonEncodedText>(
                JsonEncodedText.Encode(AuthorizeResponse.RefreshToken),
                JsonEncodedText.Encode(refreshToken)
            );
            var tokenTypePair =
            new KeyValuePair<JsonEncodedText, JsonEncodedText>(
                JsonEncodedText.Encode(AuthorizeResponse.TokenType),
                JsonEncodedText.Encode(tokenType)
            );
            var expiredTimePair = new KeyValuePair<JsonEncodedText, JsonEncodedText>(
                JsonEncodedText.Encode(AuthorizeResponse.ExpiresIn),
                JsonEncodedText.Encode(((long)(expiredTime - DateTime.Now).TotalSeconds).ToString())
            );

            return new TokenResponseValuePairs(accessTokenPair, refreshTokenPair, expiredTimePair, tokenTypePair, idTokenPair);
        }

        private static async Task<string> CreateTokenJsonStringAsync(TokenResponseValuePairs pairs)
        {
            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream);
            {
                writer.WriteStartObject();
                writer.WriteString(pairs.AccessToken.Key, pairs.AccessToken.Value);
                if (!string.IsNullOrEmpty(pairs.RefreshToken.Value.Value))
                    writer.WriteString(pairs.RefreshToken.Key, pairs.RefreshToken.Value);
                writer.WriteString(pairs.ExpiredTime.Key, pairs.ExpiredTime.Value);
                if (!string.IsNullOrEmpty(pairs.TokenType.Value.Value))
                    writer.WriteString(pairs.TokenType.Key, pairs.TokenType.Value);
                writer.WriteString(pairs.IdToken.Key, pairs.IdToken.Value);
                writer.WriteEndObject();

                await writer.FlushAsync();
            }

            string json = Encoding.UTF8.GetString(stream.ToArray());
            return json;
        }

        #region user info to json
        public static async Task<string> CreateUserInfoResponseAsync(Models.DbModel.UserIdentity user)
        {
            UserInfoValuePairs valuePairs = await Task.Run(() => ConvertUserInfoToUTF8(user.UserName, user.FullName, user.Email, user.EmailConfirmed, user.Avatar));
            string json = await CreateUserInforJsonStringAsync(valuePairs);

            return json;
        }

        private static UserInfoValuePairs ConvertUserInfoToUTF8(string userName, string fullName, string email, bool emailConfirmed, string avatar)
        {
            var sub = new KeyValuePair<JsonEncodedText, JsonEncodedText>(
                JsonEncodedText.Encode(UserInforResponse.Sub),
                JsonEncodedText.Encode(userName));
            var name = new KeyValuePair<JsonEncodedText, JsonEncodedText>(
                JsonEncodedText.Encode(UserInforResponse.Name),
                JsonEncodedText.Encode(fullName));
            var emailValuePairs = new KeyValuePair<JsonEncodedText, JsonEncodedText>(
                JsonEncodedText.Encode(UserInforResponse.Email),
                JsonEncodedText.Encode(email));
            var emailConfirmedValuePairs = new KeyValuePair<JsonEncodedText, JsonEncodedText>(
                JsonEncodedText.Encode(UserInforResponse.EmailConfirmed),
                JsonEncodedText.Encode(emailConfirmed.ToString()));
            var picture = new KeyValuePair<JsonEncodedText, JsonEncodedText>(
                JsonEncodedText.Encode(UserInforResponse.Picture),
                JsonEncodedText.Encode(avatar));

            return new UserInfoValuePairs(sub, name, emailValuePairs, emailConfirmedValuePairs, picture);
        }

        private static async Task<string> CreateUserInforJsonStringAsync(UserInfoValuePairs valuePairs)
        {
            var name = HttpUtility.UrlDecode(Encoding.UTF8.GetString(valuePairs.Name.Value.EncodedUtf8Bytes));
            var stream = new MemoryStream();
            var writer = new Utf8JsonWriter(stream);
            {
                writer.WriteStartObject();
                writer.WriteString(valuePairs.Sub.Key, valuePairs.Sub.Value);
                writer.WriteString(valuePairs.Name.Key, valuePairs.Name.Value);
                writer.WriteString(valuePairs.Email.Key, valuePairs.Email.Value);
                writer.WriteString(valuePairs.EmailConfirmed.Key, valuePairs.EmailConfirmed.Value);
                writer.WriteString(valuePairs.Picture.Key, valuePairs.Picture.Value);
                writer.WriteEndObject();

                await writer.FlushAsync();
            }

            string json = Encoding.UTF8.GetString(stream.ToArray());
            return json;
        }
        #endregion

        private record TokenResponseValuePairs(
            KeyValuePair<JsonEncodedText, JsonEncodedText> AccessToken,
            KeyValuePair<JsonEncodedText, JsonEncodedText> RefreshToken,
            KeyValuePair<JsonEncodedText, JsonEncodedText> ExpiredTime,
            KeyValuePair<JsonEncodedText, JsonEncodedText> TokenType,
            KeyValuePair<JsonEncodedText, JsonEncodedText> IdToken);

        private record UserInfoValuePairs(
            KeyValuePair<JsonEncodedText, JsonEncodedText> Sub,
            KeyValuePair<JsonEncodedText, JsonEncodedText> Name,
            KeyValuePair<JsonEncodedText, JsonEncodedText> Email,
            KeyValuePair<JsonEncodedText, JsonEncodedText> EmailConfirmed,
            KeyValuePair<JsonEncodedText, JsonEncodedText> Picture);


        public static Dictionary<DefaultResponseMessage, JsonEncodedText> ResponseMessages = new Dictionary<DefaultResponseMessage, JsonEncodedText>()
        {
            { DefaultResponseMessage.EmailIsConfirmed, JsonEncodedText.Encode("Email is confirmed!") },
            { DefaultResponseMessage.ResponseModeNotAllowed, JsonEncodedText.Encode(ExceptionMessage.RESPONSE_MODE_NOT_ALLOWED) }
        };
        #endregion
    }
}
