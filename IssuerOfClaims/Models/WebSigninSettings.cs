namespace IssuerOfClaims.Models
{
    public record WebSigninSettings(
        string Origin,
        string AllowedMethods,
        string SigninUri,
        string ConsentPromptUri,
        string RegisterUri, 
        string AllowHeaders, 
        string AllowCredentials, 
        string ForgetPasswordUri,
        string ChangePasswordUri);
}
