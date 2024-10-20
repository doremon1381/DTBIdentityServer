using System.Drawing.Imaging;
using System.Drawing;
using static ServerUltilities.Identity.OidcConstants;
using System.Text.Json;
using System.Text;

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

        public static DateTime TimeSecondsToDateTime(long timeSeconds)
        {
            DateTime start = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            return start.AddSeconds(timeSeconds).ToLocalTime();
        }



        /// <summary>
        /// To achieve optimal performance, write JSON payloads that are already encoded as UTF-8 text rather than as UTF-16 strings. 
        /// <para> Use JsonEncodedText to cache and pre-encode known property names and values as statics.</para>
        /// <para> Powered by Copilot </para>
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="idToken"></param>
        /// <param name="expiredTimeSeconds"></param>
        /// <param name="refreshToken"></param>
        public static async Task<string> CreateTokenResponseStringAsync(string accessToken, string idToken, long expiredTimeSeconds, string refreshToken = "", string tokenType = TokenResponse.BearerTokenType)
        {
            var propertyValuePairs = await ConvertResponseStringToUTF8Async(accessToken, idToken, refreshToken, expiredTimeSeconds, tokenType);

            var json = await CreateJsonStringAsync(propertyValuePairs);

            return json;
        }

        private static async Task<string> CreateJsonStringAsync(ParameterValuePairs propertyValuePairs)
        {
            var stream = new MemoryStream();
            var writer = new Utf8JsonWriter(stream);

            writer.WriteStartObject();
            writer.WriteString(propertyValuePairs.AccessTokenPair.Key, propertyValuePairs.AccessTokenPair.Value);
            if (!string.IsNullOrEmpty(propertyValuePairs.RefreshTokenPair.Value.Value))
                writer.WriteString(propertyValuePairs.RefreshTokenPair.Key, propertyValuePairs.RefreshTokenPair.Value);
            writer.WriteString(propertyValuePairs.ExpiredTimePair.Key, propertyValuePairs.ExpiredTimePair.Value);
            if (!string.IsNullOrEmpty(propertyValuePairs.TokenTypePair.Value.Value))
                writer.WriteString(propertyValuePairs.TokenTypePair.Key, propertyValuePairs.TokenTypePair.Value);
            writer.WriteString(propertyValuePairs.IdTokenPair.Key, propertyValuePairs.IdTokenPair.Value);
            writer.WriteEndObject();

            writer.Flush();

            string json = Encoding.UTF8.GetString(stream.ToArray());
            return json;
        }

        private static async Task<ParameterValuePairs>ConvertResponseStringToUTF8Async(string accessToken, string idToken, string refreshToken, long expiredTimeSeconds, string tokenType)
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
                JsonEncodedText.Encode(TimeSecondsToDateTime(expiredTimeSeconds).ToString())
            );

            return new ParameterValuePairs(accessTokenPair, refreshTokenPair, expiredTimePair, tokenTypePair, idTokenPair);
        }

        private record ParameterValuePairs(
            KeyValuePair<JsonEncodedText, JsonEncodedText> AccessTokenPair, 
            KeyValuePair<JsonEncodedText, JsonEncodedText> RefreshTokenPair, 
            KeyValuePair<JsonEncodedText, JsonEncodedText> ExpiredTimePair,
            KeyValuePair<JsonEncodedText, JsonEncodedText> TokenTypePair,
            KeyValuePair<JsonEncodedText, JsonEncodedText> IdTokenPair);

    }
}
