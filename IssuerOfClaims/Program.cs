using IssuerOfClaims.Controllers.Ultility;
using IssuerOfClaims.Database;
using IssuerOfClaims.Extensions;
using IssuerOfClaims.Models;
using IssuerOfClaims.Services;
using IssuerOfClaims.Services.Database;
using IssuerOfClaims.Services.Middleware;
using IssuerOfClaims.Services.Token;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;
using ServerUltilities.Identity;

namespace IssuerOfClaims
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllers();
            builder.Services.AddDbContext<IDbContextManager, DbContextManager>(optionsAction =>
            {
                optionsAction.UseSqlServer(builder.Configuration.GetConnectionString(DbUtilities.DatabaseName));
            }, ServiceLifetime.Transient);

            builder.Services.AddLogging(options =>
            {
                //options.AddFilter("Duende", LogLevel.Debug);
            });

            var webSigninSettings = Utilities.GetWebSigninSettings(builder.Configuration);
            builder.Services.AddSingleton<IConfigurationManager>(builder.Configuration);
            builder.Services.AddSingleton<GoogleClientConfiguration>(Utilities.GetGoogleClientSettings(builder.Configuration));
            builder.Services.AddSingleton<WebSigninSettings>(webSigninSettings);
            // TODO: will change later
            builder.Services.AddTransient<IClientDbServices, ClientDbServices>();
            builder.Services.AddTransient<IRoleDbServices, RoleDbServices>();
            builder.Services.AddTransient<IConfirmEmailDbServices, ConfirmEmailDbServices>();
            builder.Services.AddTransient<ITokenResponseDbServices, TokenResponseDbServices>();
            builder.Services.AddTransient<IIdentityRequestSessionDbServices, IdentityRequestSessionDbServices>();
            builder.Services.AddTransient<ITokenForRequestHandlerDbServices, TokenForRequestHandlerDbServices>();
            builder.Services.AddTransient<IIdentityRequestHandlerDbServices, IdentityRequestHandlerDbServices>();
            builder.Services.AddTransient<IEmailServices, EmailServices>();
            builder.Services.AddTransient<ITokenManager, TokenManager>();

            // TODO: will add later
            builder.Services.AddIdentityCore<UserIdentity>()
                //.AddSignInManager<SignInServices>()
                .AddEntityFrameworkStores<DbContextManager>()
                .AddDefaultTokenProviders();
            builder.Services.AddTransient<IApplicationUserManager, ApplicationUserManager>();
            // TODO: comment for now
            //builder.Services.AddApiVersioning(apiVersionOptions =>
            //{
            //    apiVersionOptions.DefaultApiVersion = new ApiVersion(1, 0);
            //    apiVersionOptions.AssumeDefaultVersionWhenUnspecified = true;
            //    apiVersionOptions.ReportApiVersions = true;
            //});

            //builder.Services.AddDistributedMemoryCache();
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer;
                //options.DefaultForbidScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            //.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
            .AddScheme<JwtBearerOptions, AuthenticationServices>(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer,
                options =>
                {
                    // TODO: will check later
                    //options.Authority = "PrMIdentityServer";
                    //options.Audience = "http://localhost:3010/";
                    builder.Configuration.Bind("Jwt", options);
                    //options.TokenValidationParameters = new TokenValidationParameters
                    //{
                    //    ValidateIssuer = true,
                    //    //ValidIssuer = "my-firebase-project",
                    //    ValidateAudience = true,
                    //    //ValidAudience = "my-firebase-project",
                    //    ValidateLifetime = true
                    //};
                });
            builder.Services.AddMvc(mvcOptions =>
            {
                mvcOptions.Conventions.Add(new ControllerNameAttributeConvention());
            });
            builder.Services.AddCors(options =>
            {
                options.AddPolicy(name: "AllowFrontEnd",
                    policy =>
                    {
                        policy.WithOrigins(webSigninSettings.Origin)
                            .WithMethods("PUT", "DELETE", "GET", "POST", "OPTIONS")
                            .AllowAnyHeader();
                    });
            });
            var app = builder.Build();
            // TODO: use for initiate clients in database
            AuthorizationResources.CreateClient(builder.Configuration);
            SetupPipline(app);
            // I intentionally separate app.run with setupPipline
            // , it's not official protocol as far as I know
            app.Run();
        }

        static void SetupPipline(WebApplication app)
        {
            // Configure the HTTP request pipeline.

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();
            app.UseCors("AllowFrontEnd");

            app.UseAuthentication();
            // TODO: redirect to login web when catch 401 response
            app.UseMiddleware<RedirectAuthenticationMiddleware>();
            app.UseAuthorization();

            // TODO: comment for now
            //app.UseSession();
            app.MapControllers();
            app.UseMiddleware<ExceptionHandlerMiddleware>();
        }
    }
}
