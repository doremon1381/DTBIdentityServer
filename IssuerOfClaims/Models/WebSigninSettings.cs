namespace IssuerOfClaims.Models
{
    public record WebSigninSettings(
        string Origin,
        string AllowedMethods,
        string SigninUri,
        string ConsentPromptUri,
        string RegisterUri, 
        string ForgetPasswordUri,
        string ChangePasswordUri);
}
