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
using Microsoft.AspNetCore.Http;
using System.IO;

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
        public static async Task<string> SerializeFormAsync(Stream stream)
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

        #region get information from appsettings.json
        public static GoogleClientConfiguration GetGoogleClientSettings(IConfigurationManager configuration)
        {
            var googleClientConfig = configuration.GetSection(IdentityServerConfiguration.GOOGLE_CLIENT).Get<GoogleClientConfiguration>();
            ValidateGoogleClientSettings(googleClientConfig);

            return googleClientConfig;
        }

        public static WebSigninSettings GetWebSigninSettings(IConfigurationManager configuration)
        {
            var webSignin = configuration.GetSection(IdentityServerConfiguration.WEB_SIGNIN).Get<WebSigninSettings>();
            ValidateWebSigninSettings(webSignin);

            return webSignin;
        }

        private static void ValidateWebSigninSettings(WebSigninSettings? webSignin)
        {
            if (webSignin == null)
                throw new CustomException(ExceptionMessage.MISSING_WEB_SIGIN_DETAILS);

            if (webSignin == null
                || string.IsNullOrEmpty(webSignin.SigninUri)
                || string.IsNullOrEmpty(webSignin.ConsentPromptUri)
                || string.IsNullOrEmpty(webSignin.ChangePasswordUri)
                || string.IsNullOrEmpty(webSignin.ForgetPasswordUri)
                || string.IsNullOrEmpty(webSignin.RegisterUri))
                throw new CustomException(ExceptionMessage.MISSING_WEB_SIGIN_DETAILS);
        }

        private static void ValidateGoogleClientSettings(GoogleClientConfiguration? googleClientConfig)
        {
            if (googleClientConfig == null)
                throw new CustomException(ExceptionMessage.MISSING_GOOGLE_CLIENT_DETAILS);

            if (googleClientConfig == null
                || string.IsNullOrEmpty(googleClientConfig.ClientId)
                || string.IsNullOrEmpty(googleClientConfig.ClientSecret)
                || string.IsNullOrEmpty(googleClientConfig.AuthUri)
                || string.IsNullOrEmpty(googleClientConfig.TokenUri)
                || googleClientConfig.RedirectUris == null || googleClientConfig.RedirectUris.Count == 0)
                throw new CustomException(ExceptionMessage.MISSING_GOOGLE_CLIENT_DETAILS);
        }
        #endregion
    }

    public class TaskUtilities
    {
        public static async Task<T> RunAttachedToParentTask<T>(Func<T> func)
        {
            return await Task.Factory.StartNew<T>(func, TaskCreationOptions.AttachedToParent);
        }

        public static async Task RunAttachedToParentTask(Action action)
        {
            await Task.Factory.StartNew(action, TaskCreationOptions.AttachedToParent);
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

    public static class ControllerAttributeName
    {
        public const string AllowAnonymous = "AllowAnonymousAttribute";
    }

    /// <summary>
    /// Query symbols
    /// </summary>
    internal static class QS
    {
        public const string Path = "path";
        public const string OauthEndpoint = "endpoint";
        public const string Equal = "=";
        public const string Method = "method";
        public const string And = "&";
    }
}
