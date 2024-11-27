using IssuerOfClaims.Controllers.Attributes;
using IssuerOfClaims.Database;
using IssuerOfClaims.Extensions;
using IssuerOfClaims.Models;
using IssuerOfClaims.Services;
using IssuerOfClaims.Services.Authentication;
using IssuerOfClaims.Services.Database;
using IssuerOfClaims.Services.Middleware;
using IssuerOfClaims.Services.Token;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities.Identity;
using Autofac;
using System.Reflection;
using Autofac.Extensions.DependencyInjection;

namespace IssuerOfClaims
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            builder.Host.UseServiceProviderFactory(new AutofacServiceProviderFactory());

            builder.Services.AddControllers();
            builder.Services
                .AddDbContext<IDbContextManager, DbContextManager>((serviceProvider, optionsAction) =>
                {
                    optionsAction.UseSqlServer(builder.Configuration.GetConnectionString(DbUtilities.DatabasePath));
                    //.AddInterceptors(serviceProvider.GetRequiredService<SecondLevelCacheInterceptor>());
                }, ServiceLifetime.Transient);

            builder.Services.AddLogging(options =>
            {
                //options.AddFilter("Duende", LogLevel.Debug);
            });

            var webSigninSettings = Utilities.GetWebSigninSettings(builder.Configuration);
            builder.Services.AddSingleton<IConfigurationManager>(builder.Configuration);
            builder.Services.AddSingleton<GoogleClientConfiguration>(Utilities.GetGoogleClientSettings(builder.Configuration));
            builder.Services.AddSingleton<WebSigninSettings>(webSigninSettings);
            builder.Services.AddSingleton<MailSettings>(builder.Configuration.GetSection(IdentityServerConfiguration.MAILSETTINGS).Get<MailSettings>());
            builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, AuthorizationMiddlewareResultHandler>();
            //// TODO: will change later
            //builder.Services.AddTransient<IClientDbService, ClientDbService>();
            ////builder.Services.AddTransient<IRoleDbServices, RoleDbServices>();
            //builder.Services.AddTransient<IConfirmEmailDbService, ConfirmEmailDbService>();
            //builder.Services.AddTransient<ITokenResponseDbService, TokenResponseDbService>();
            //builder.Services.AddTransient<IIdentityRequestSessionDbService, IdentityRequestSessionDbService>();
            //builder.Services.AddTransient<ITokenForRequestHandlerDbService, TokenForRequestHandlerDbService>();
            //builder.Services.AddTransient<IIdentityRequestHandlerDbService, IdentityRequestHandlerDbService>();
            //builder.Services.AddTransient<IEmailService, EmailService>();
            //builder.Services.AddTransient<ITokenService, TokenService>();
            //builder.Services.AddTransient<IIdentityRequestHandlerService, RequestHanderService>();
            //builder.Services.AddTransient<IResponseManagerService, ResponseManagerService>();

            builder.Host.ConfigureContainer<ContainerBuilder>(containerBuilder =>
            {
                containerBuilder.RegisterAssemblyTypes(_Assembly)
                    .Where(t => t.Name.EndsWith("Service"))
                    .AsImplementedInterfaces()
                    .InstancePerDependency();
            });

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

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer;
            }).AddScheme<JwtBearerOptions, AuthenticationServices>(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer, options => { });

            builder.Services.AddMvc(mvcOptions =>
            {
                mvcOptions.Conventions.Add(new ControllerNameAttributeConvention());
            });

            // TODO: configure serilog, will learn about it later
            Log.Logger = new LoggerConfiguration()
                .WriteTo.Console()
                .WriteTo.File("Logs/log-.txt", rollingInterval: RollingInterval.Day)
                .CreateLogger();

            builder.Host.UseSerilog();

            // TODO: will add certificate later
            //builder.WebHost.ConfigureKestrel(serverOptions =>
            //{
            //    string certPath = builder.Configuration.GetSection("profiles:IssuerOfClaims:environmentVariables:CERTIFICATE_PATH").Value;
            //    string certPassword = builder.Configuration.GetSection("profiles:IssuerOfClaims:environmentVariables:CERTIFICATE_PASSWORD").Value;
            //    serverOptions.ListenAnyIP(7180, listenOptions =>
            //    {
            //        listenOptions.UseHttps(certPath, certPassword);
            //    });
            //});
            builder.MigrateDatabase();

            var app = builder.Build();
            SetupPipline(app);
            // I intentionally separate app.run with setupPipline
            // , it's not official protocol as far as I know
            app.Run();
        }

        private static Assembly _Assembly => typeof(Program).GetTypeInfo().Assembly;

        static void SetupPipline(WebApplication app)
        {
            // Configure the HTTP request pipeline.

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();
            app.UseMiddleware<ApplyCORSMiddleware>();

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
