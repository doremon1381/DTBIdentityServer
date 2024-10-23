- tool for test: https://github.com/doremon1381/ToolTestForIS <br>
___________________________________________________________________________________________________________________ <br>

### <strong>1. Overview</strong> <br>
This project is an attempt to implement OpenID specification (https://openid.net/specs/openid-connect-core-1_0-final.html), <br>
using .NET core and EF core.

### <strong>2. How to build</strong> <br>
- Install the latest .NET 8.0 SDK. <br>
- Clone this repo. <br>
- Run IssuerOfClaims.sln in "IssuerOfClaims" folder of the cloned repo. <br>
- Migration database before using database. (https://learn.microsoft.com/en-us/ef/core/managing-schemas/migrations/?tabs=dotnet-core-cli) <br>

### <strong>3. Endpoints currently suport</strong> <br>
- Run "IssuerOfClaims.sln" and goto discovery endpoint (<em>https://{yourDomain}/.well-known/openid-configuration</em>). <br>

### <strong>4. Ongoing</strong> <br>
- Other endpoints. <br>
- Login, consent and user information UI. <br>
- Other updates in future (adding new endpoint may need to update code logic or database). <br>

Will update services's description later!
