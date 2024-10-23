using System.Drawing.Imaging;
using System.Drawing;
using static ServerUltilities.Identity.OidcConstants;
using System.Text.Json;
using System.Text;
using static ServerUltilities.Identity.IdentityServerConstants;
using IssuerOfClaims.Models;
using System.Net;
using System.Web;
using ServerUltilities.Identity;

namespace IssuerOfClaims.Extensions
{
    public static class Utilities
    {
        /// <summary>
        /// https://stackoverflow.com/questions/1922040/how-to-resize-an-image-c-sharp
        /// </summary>
        /// <param name="newWidth"></param>
        /// <param name="newHeight"></param>
        /// <param name="stPhotoPath"></param>
        /// <returns></returns>
        public static Image ResizeImageToBitmap(int newWidth, int newHeight, string stPhotoPath)
        {
            Image imgPhoto = Image.FromFile(stPhotoPath);

            int sourceWidth = imgPhoto.Width;
            int sourceHeight = imgPhoto.Height;

            //Consider vertical pics
            if (sourceWidth < sourceHeight)
            {
                int buff = newWidth;

                newWidth = newHeight;
                newHeight = buff;
            }

            int sourceX = 0, sourceY = 0, destX = 0, destY = 0;
            float nPercent = 0, nPercentW = 0, nPercentH = 0;

            nPercentW = ((float)newWidth / (float)sourceWidth);
            nPercentH = ((float)newHeight / (float)sourceHeight);
            if (nPercentH < nPercentW)
            {
                nPercent = nPercentH;
                destX = System.Convert.ToInt16((newWidth -
                          (sourceWidth * nPercent)) / 2);
            }
            else
            {
                nPercent = nPercentW;
                destY = System.Convert.ToInt16((newHeight -
                          (sourceHeight * nPercent)) / 2);
            }

            int destWidth = (int)(sourceWidth * nPercent);
            int destHeight = (int)(sourceHeight * nPercent);


            Bitmap bmPhoto = new Bitmap(newWidth, newHeight,
                          PixelFormat.Format24bppRgb);

            bmPhoto.SetResolution(imgPhoto.HorizontalResolution,
                         imgPhoto.VerticalResolution);

            Graphics grPhoto = Graphics.FromImage(bmPhoto);
            grPhoto.Clear(Color.Black);
            grPhoto.InterpolationMode =
                System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;

            grPhoto.DrawImage(imgPhoto,
                new Rectangle(destX, destY, destWidth, destHeight),
                new Rectangle(sourceX, sourceY, sourceWidth, sourceHeight),
                GraphicsUnit.Pixel);

            grPhoto.Dispose();
            imgPhoto.Dispose();
            return bmPhoto;
        }

        public static DateTime Google_TimeSecondsToDateTime(long timeSeconds)
        {
            DateTime start = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            return start.AddSeconds(timeSeconds).ToLocalTime();
        }

        /// <summary>
        /// get parameter from HttpContext.Request.Body
        /// </summary>
        /// <param name="stream">HttpContext.Request.Body</param>
        /// <returns></returns>
        /// <exception cref="InvalidDataException"></exception>
        public static async Task<string> GetRequestBodyAsQueryFormAsync(Stream stream)
        {
            string content = "";
            using (StreamReader reader = new StreamReader(stream))
            {
                content = await reader.ReadToEndAsync();
                // TODO: add '?' to match request query form
                content = "?" + content;
            }

            if (string.IsNullOrEmpty(content))
                throw new CustomException(ExceptionMessage.REQUEST_BODY_NOT_NULL_OR_EMPTY, HttpStatusCode.BadRequest);

            return content;
        }

        #region issue token response json
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
            var valuePairs = await ConvertResponseStringToUTF8Async(accessToken, idToken, refreshToken, expiredInDateTime, tokenType);
            var json = await CreateTokenJsonStringAsync(valuePairs);

            return json;
        }

        public static async Task<string> CreateUserInfoResponseAsync(ServerDbModels.UserIdentity user)
        {
            UserInfoValuePairs valuePairs = await ConvertUserInfoToUTF8Async(user.UserName, user.FullName, user.Email, user.EmailConfirmed, user.Avatar);
            string json = await CreateUserInforJsonStringAsync(valuePairs);

            return json;
        }

        public static async Task<string> CreateDiscoveryResponseAsync(Dictionary<string, string> dictionary)
        {
            Dictionary<JsonEncodedText, JsonEncodedText> valuePairs = await ConverDiscoveryEndpointsToUTF8Async(dictionary);

            string json = await CreateDiscoveryEndpointsJsonStringAsync(valuePairs);

            return json;
        }

        private static async Task<string> CreateDiscoveryEndpointsJsonStringAsync(Dictionary<JsonEncodedText, JsonEncodedText> valuePairs)
        {
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();

                foreach (var key in valuePairs.Keys)
                {
                    writer.WriteString(key, valuePairs[key]);
                }
                writer.WriteEndObject();

                await writer.FlushAsync();
            }

            return Encoding.UTF8.GetString(stream.ToArray());
        }

        private static async Task<Dictionary<JsonEncodedText, JsonEncodedText>> ConverDiscoveryEndpointsToUTF8Async(Dictionary<string, string> dictionary)
        {
            var dic = new Dictionary<JsonEncodedText, JsonEncodedText>();

            foreach (var key in dictionary.Keys)
            {
                dic.Add(JsonEncodedText.Encode(key), JsonEncodedText.Encode(dictionary[key]));
            }

            return dic;
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

                writer.Flush();
            }

            string json = Encoding.UTF8.GetString(stream.ToArray());
            return json;
        }

        private static async Task<UserInfoValuePairs> ConvertUserInfoToUTF8Async(string userName, string fullName, string email, bool emailConfirmed, string avatar)
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

                writer.Flush();
            }

            string json = Encoding.UTF8.GetString(stream.ToArray());
            return json;
        }

        private static async Task<TokenResponseValuePairs> ConvertResponseStringToUTF8Async(string accessToken, string idToken, string refreshToken, DateTime expiredTime, string tokenType)
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

        public static GoogleClientConfiguration GetGoogleClientSettingsFromAppsettings(IConfigurationManager configuration)
        {
            var googleClientConfig = configuration.GetSection(IdentityServerConfiguration.GOOGLE_CLIENT).Get<GoogleClientConfiguration>();
            ValidateGoogleClientSettings(googleClientConfig);

            return googleClientConfig;
        }

        private static void ValidateGoogleClientSettings(GoogleClientConfiguration? googleClientConfig)
        {
            if (googleClientConfig == null)
                throw new CustomException("Elaboration of google inside server is mismatch!");

            if (googleClientConfig == null
                || string.IsNullOrEmpty(googleClientConfig.ClientId)
                || string.IsNullOrEmpty(googleClientConfig.ClientSecret)
                || string.IsNullOrEmpty(googleClientConfig.AuthUri)
                || string.IsNullOrEmpty(googleClientConfig.TokenUri)
                || googleClientConfig.RedirectUris == null || googleClientConfig.RedirectUris.Count == 0)
                throw new CustomException("Elaboration of google inside server is mismatch!");
        }
    }

    public enum DefaultResponseMessage
    {
        EmailIsConfirmed,
        ResponseModeNotAllowed,
    }

    public static class ExternalSources
    {
        public const string Google = "Google";
        public const string FaceBook = "Facebook";
        public const string Twitter = "Twitter";
        //...
    }
}
