using System.Drawing.Imaging;
using System.Drawing;
using System.Text;
using IssuerOfClaims.Models;
using System.Net;
using ServerUltilities.Identity;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using ServerUltilities;
using ServerUltilities.Extensions;

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

        public static bool IsOptions(this string httpMethod)
        {
            return httpMethod.Equals("OPTIONS");
        }
    }

    public static class RSAEncryptUtilities
    {
        #region Implement RsaSha256, powered by copilot
        private static readonly object lockObj = new object();
        /// <summary>
        /// for this pair, key is rsa private key, value is rsa public key
        /// </summary>
        /// <returns></returns>
        public static (RSAParameters PrivateKey, RSAParameters PublicKey) CreateRsaPublicKeyAndPrivateKey()
        {
            RSAParameters publicKey;
            RSAParameters privateKey;

            if (KeyCanNotBeReused())
            {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    // Get the public and private key
                    publicKey = rsa.ExportParameters(false); // Public key
                    privateKey = rsa.ExportParameters(true); // Private key

                    // Store or distribute these keys securely                
                }

                ExportJsonKey(publicKey);
                ExportJsonKey(privateKey, isPublicKey: false);
            }
            else
            {
                publicKey = ReadJsonKey(); // Public key
                privateKey = ReadJsonKey(isPublicKey: false); // Private key
            }

            return new(privateKey, publicKey);
        }

        private static bool KeyCanNotBeReused(bool isPublicKey = true)
        {
            FileInfo keyFile = new FileInfo(GetKeyFilePath(isPublicKey));

            if (keyFile.Exists)
            {
                return keyFile.LastWriteTimeUtc.AddDays(15) <= DateTime.Now;
            }

            return true;
        }

        private static string GetKeyFilePath(bool isPublicKey)
        {
            return isPublicKey switch
            {
                true => $"{Environment.CurrentDirectory}\\Services\\Token\\RsaSha256Keys\\Rsa_publicKey.json",
                false => $"{Environment.CurrentDirectory}\\Services\\Token\\RsaSha256Keys\\Rsa_privateKey.json",
            };
        }

        private static void ExportJsonKey(RSAParameters key, bool isPublicKey = true)
        {
            FileInfo keyFile = new FileInfo(GetKeyFilePath(isPublicKey));

            using (FileStream fs = keyFile.Open(FileMode.OpenOrCreate))
            {
                var contents = JsonConvert.SerializeObject(key);
                Byte[] bytes = new UTF8Encoding(true).GetBytes(contents);

                fs.Write(bytes, 0, bytes.Length);
            }
        }

        public static RSAParameters ReadJsonKey(bool isPublicKey = true)
        {
            FileInfo keyFile = new FileInfo(GetKeyFilePath(isPublicKey));
            RSAParameters result = default;
            if (keyFile.Exists)
            {
                StringBuilder text = new StringBuilder();
                using (var stream = keyFile.OpenText())
                {
                    text.Append(stream.ReadToEnd());
                }
                result = JsonConvert.DeserializeObject<RSAParameters>(text.ToString());
            }
            // TODO: will check again
            else
                throw new CustomException("public key is missing!", HttpStatusCode.InternalServerError);

            return result;
        }

        private static object GetJsonPublicKey(RSAParameters publicKey)
        {
            var jsonObj = JsonConvert.SerializeObject(publicKey);
            return jsonObj;
        }

        // Encrypt using recipient's public key
        private static byte[] Encrypt(byte[] data, RSAParameters publicKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);
                return rsa.Encrypt(data, true); // Use OAEP padding for security
            }
        }

        // Decrypt using recipient's private key
        private static byte[] Decrypt(byte[] encryptedData, RSAParameters privateKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKey);
                return rsa.Decrypt(encryptedData, true);
            }
        }

        // Sign data using SHA-256 and RSA
        private static byte[] SignData(byte[] data, RSAParameters privateKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKey);
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(data);
                    return rsa.SignHash(hash, CryptoConfig.MapNameToOID(SecurityAlgorithms.Sha256));
                }
            }
        }

        // Verify signature
        private static bool VerifySignature(byte[] data, byte[] signature, RSAParameters publicKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(data);
                    return rsa.VerifyHash(hash, CryptoConfig.MapNameToOID(SecurityAlgorithms.Sha256), signature);
                }
            }
        }

        public static void VeriryJwtSignature(RSAParameters publicKey, string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            // Verify JWT signature
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(publicKey),
                ValidateIssuer = false, // Customize as needed
                ValidateAudience = false, // Customize as needed
            };

            var claimsPrincipal = tokenHandler.ValidateToken(token, validationParameters, out _);
            // 'claimsPrincipal' contains the validated claims
        }
        #endregion

        internal static T GetServiceLazily<T>(this IServiceProvider serviceProvider, ref T service)
        {
            service = service ?? serviceProvider.GetService<T>()
                ?? throw new CustomException("Cannot resolve service from asp.net core container!");

            return service;
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
        public const string Flow = "flow";
        public const string Equal = "=";
        public const string Method = "method";
        public const string And = "&";
    }
}
