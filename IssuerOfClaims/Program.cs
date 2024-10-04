using IssuerOfClaims.Controllers.Ultility;
using IssuerOfClaims.Database;
using IssuerOfClaims.Models;
using IssuerOfClaims.Services;
using IssuerOfClaims.Services.Database;
using IssuerOfClaims.Services.Token;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

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
                optionsAction.UseSqlServer(builder.Configuration.GetConnectionString(DbUltilities.DatabaseName));
            }, ServiceLifetime.Transient);

            builder.Services.AddLogging(options =>
            {
                //options.AddFilter("Duende", LogLevel.Debug);
            });

            builder.Services.AddSingleton<IConfigurationManager>(builder.Configuration);
            // TODO: will change later
            builder.Services.AddTransient<IClientDbServices, ClientDbServices>();
            builder.Services.AddTransient<IRoleDbServices, RoleDbServices>();
            builder.Services.AddTransient<IConfirmEmailDbServices, ConfirmEmailDbServices>();
            builder.Services.AddTransient<ITokenResponseDbServices, TokenResponseDbServices>();
            builder.Services.AddTransient<ITokenRequestSessionDbServices, TokenRequestSessionDbServices>();
            builder.Services.AddTransient<ITokenResponsePerHandlerDbServices, TokenResponsePerHandlerDbServices>();
            builder.Services.AddTransient<ITokenRequestHandlerDbServices, TokenRequestHandlerDbServices>();
            builder.Services.AddTransient<IIdTokenDbServices, IdTokenDbServices>();
            builder.Services.AddTransient<IEmailServices, EmailServices>();
            builder.Services.AddTransient<ITokenManager, TokenManager>();

            builder.Services.AddSingleton(builder.Configuration.GetSection("MailSettings").Get<MailSettings>());
            builder.Services.AddSingleton(builder.Configuration.GetSection("Jwt").Get<JwtOptions>());
            // TODO: will add later
            builder.Services.AddIdentityCore<UserIdentity>()
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
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultForbidScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            //.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
            .AddScheme<JwtBearerOptions, AuthenticationServices>(JwtBearerDefaults.AuthenticationScheme,
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
            //builder.Services.AddAuthorization(options => 
            //{
            //    options.AddPolicy("RequireClient", policy => policy.RequireRole("client"));
            //});
            builder.Services.AddMvc(mvcOptions =>
            {
                mvcOptions.Conventions.Add(new ControllerNameAttributeConvention());
            });
            // TODO: comment for now
            //builder.Services.AddCors(options =>
            //{
            //    options.AddPolicy(name: "MyPolicy",
            //        policy =>
            //        {
            //            policy.WithOrigins("http://localhost:5173")
            //                .WithMethods("PUT", "DELETE", "GET", "POST", "OPTIONS");
            //        });
            //});
            var app = builder.Build();
            // TODO: use for first time run db
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
            // TODO: comment for now
            //app.UseCors("MyPolicy");

            app.UseAuthentication();
            // TODO: deal with CORS, may change in the future
            //     : https://www.codemzy.com/blog/get-axios-response-headers
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Append("Access-Control-Allow-Origin", "*");
                context.Response.Headers.Append("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS");
                context.Response.Headers.Append("Access-Control-Allow-Headers", "Origin, Content-Type, X-Auth-Token, Authorization, Register");
                context.Response.Headers.Append("Access-Control-Allow-Credentials", "true");
                context.Response.Headers.Append("Access-Control-Expose-Headers", "x-version, Location, location");

                string endpointUrl = context.Request.Host.ToString();

                // TODO: for now, I assume that every request using this particular method and endpoint, is used for preflight in CORS, I will learn about it later
                if (context.Request.Method.Equals("OPTIONS") && endpointUrl.Equals("localhost:7180"))
                {
                    context.Response.StatusCode = 200;
                    return;// Short-circuit the pipeline, preventing further middleware execution
                }

                await next(context);
            });
            app.UseAuthorization();

            // TODO: comment for now
            //app.UseSession();
            app.MapControllers();
        }
    }
}
