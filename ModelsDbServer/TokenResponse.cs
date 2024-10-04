using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace ServerDbModels
{
    [Table("TokenResponses")]
    [PrimaryKey(nameof(Id))]
    public class TokenResponse : DbModelBase
    {
        public string Token { get; set; } = string.Empty;

        public string TokenType { get; set; } = string.Empty;

        public string ExternalSource { get; set;} = string.Empty;

        /// <summary>
        /// TODO: set by seconds
        /// </summary>
        public DateTime? TokenExpiried { get; set; }

        List<TokenResponsePerIdentityRequest> TokenResponsePerHandler { get; set; } = new List<TokenResponsePerIdentityRequest>();
    }

    public static class TokenType
    {
        public const string AccessToken = "access_token";
        public const string IdToken = "id_token";
        public const string RefreshToken = "refresh_token";
    }

    public enum ExternalSources
    {
        Google,
        FaceBook,
        Twitter
        //...
    }
}
