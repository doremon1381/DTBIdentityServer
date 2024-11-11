- tool for test: https://github.com/doremon1381/ToolTestForIS <br>
___________________________________________________________________________________________________________________ <br>

### <strong>1. Overview</strong> <br>
This project is an attempt to implement OpenID specification (https://openid.net/specs/openid-connect-core-1_0-final.html), <br>
using .NET core and EF core.

### <strong>2. Before running project</strong><br>
* You must replace <em><strong>"GoogleClient"</strong></em>'s value inside <em><strong>"appsettings.json"</strong></em> to your Google client information (how to get: https://support.google.com/cloud/answer/6158849?hl=en).<br>
And add <em><strong>"ClientSecret":"{your google client secret}"</strong></em> into <em><strong>"GoogleClient"</strong></em>'s value (inside <em><strong>appsettings.json</strong></em>).<br>
In OAuth protocol, it means, your Google client information will be used to form a relation between this application and Google identity server (under the name of your identity from Google), as a "<em>client</em>".<br>
(Still inside Oauth protocol) After that, this application can delegate authorization requests to and get access to resources from Google identity server.<br>
-- More information: https://datatracker.ietf.org/doc/html/rfc6749#section-1.1<br>
* You must replace <em><strong>"EmailId"</strong></em>'s value and <em><strong>"UserName"</strong></em>'s value of <em><strong>"MailSettings"</strong></em> inside <em><strong>appsettings.json</strong></em> to your Google email's information.<br>
And add <em><strong>"Password":"{your password from Google}"</strong></em> into <em><strong>"MailSettings"</strong></em>'s value (inside <em><strong>appsettings.json</strong></em>).<br>
This application currently uses these settings for Mailkit's configuration to programmatically send email from a particular Google email (in this context, your Google email). Sending an email will occur inside a user register's process or some other processes.<br>
Updating for support from other email service providers will be later.<br>
-- How to get <em><strong>"MailSettings"</strong></em>'s <em><strong>"Password"</strong></em>: https://stackoverflow.com/questions/72543208/how-to-use-mailkit-with-google-after-may-30-2022 <br>
-- For more information: https://mailtrap.io/blog/csharp-send-email-gmail/#How-to-send-email-using-Gmail-SMTP-server-in-C<br>

### <strong>3. How to build</strong> <br>
- Install the latest .NET 8.0 SDK. <br>
- Clone this repo. <br>
- Run <em><strong>IssuerOfClaims.sln</strong></em> in <em><strong>"IssuerOfClaims"</strong></em> folder of the cloned repo. <br>
- Migration database before using a database. (https://learn.microsoft.com/en-us/ef/core/managing-schemas/migrations/?tabs=dotnet-core-cli).<br>
- Build and run <br>

### <strong>4. Endpoints currently suport</strong> <br>
- Run <em><strong>IssuerOfClaims.sln</strong></em> and goto discovery endpoint (<em>https://{yourDomain}/.well-known/openid-configuration</em>). <br>

### <strong>5. Ongoing</strong> <br>
- Other endpoints. <br>
- Adding device registration. <be>
- Update login, consent, and user information UI. <br>
- Other updates in the future (adding new endpoint may need to update code logic or database). <br>
- Apply some changes to use Redis. <br>

Will update this description later!
