namespace ServerDbModels
{
    public class MailSettings
    {
        public string EmailId { get; set; }
        public string Name { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Host { get; set; }
        public int Port { get; set; }
        public bool UseSSL { get; set; }
        public bool DefaultCredentials {  get; set; }
    }

    public static class MailKitConfig
    {
        public const string EMAIL_ID = "EmailId";
        public const string NAME = "Name";
        public const string USER_NAME = "UserName";
        public const string PASSWORD = "Password";
        public const string HOST = "Host";
        public const string PORT = "Port";
        public const string USESSL = "Usessl";
        public const string DEFAULT_CREDENTIALS = "Default_credentials";
    }
}
