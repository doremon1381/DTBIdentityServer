using IssuerOfClaims.Database;
using IssuerOfClaims.Models.DbModel;
using IssuerOfClaims.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Newtonsoft.Json;
using Org.BouncyCastle.Utilities;
using System.Text;

namespace IssuerOfClaims
{
    public static class ApplicationExtensions
    {
        public static IHostApplicationBuilder MigrateDatabase(this IHostApplicationBuilder builder)
        {
            var serviceProvider = builder.Services.BuildServiceProvider();

            // 5.9.2 Having your application migrate your database on startup
            // Creates a scoped service provider. After the using
            // block is left, all the services will be unavailable. This
            // is the recommended way to obtain services outside an HTTP request.
            using (var scope = serviceProvider.CreateScope())
            {
                using (var context = serviceProvider.GetService<DbContextManager>())
                {
                    try
                    {
                        var databaseIsExist = (context.Database.GetService<IDatabaseCreator>() as RelationalDatabaseCreator).Exists();

                        // call ef core to apply migration at application startup
                        if (!databaseIsExist)
                        {
                            // create new database using migration
                            context.Database.Migrate();

                            // create new user
                            var user = CreateFirstUser(serviceProvider);
                            // TODO: use for initiate clients in database
                            AuthorizationResources.CreateClient(context, user);
                        }
                        else
                        {
                            // update for latest changing
                            context.Database.Migrate();
                        }

                    }
                    catch (Exception ex)
                    {
                        // TODO: error at this step
                        var logger = serviceProvider.GetRequiredService<ILogger>();
                        logger.LogError(ex, "An error occured while migrate database!");

                        throw;
                    }
                }

            }

            return builder;
        }

        // TODO: add for test
        private static void GetUsersJson(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var userManager = serviceProvider.GetService<IApplicationUserManager>();

                var allUsers = JsonConvert.SerializeObject(userManager.Current.Users.ToList());

                FileInfo usersList = new FileInfo($"{Environment.CurrentDirectory}\\users.json");
                using (FileStream stream = usersList.Open(FileMode.OpenOrCreate))
                {
                    Byte[] bytes = new UTF8Encoding().GetBytes(allUsers);
                    stream.Write(bytes, 0, bytes.Length);
                }
            }
        }

        private static UserIdentity CreateFirstUser(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var dbContext = serviceProvider.GetService<DbContextManager>();
                var userDbSet = dbContext.GetDbSet<UserIdentity>();

                return userDbSet.First();
            }
        }
    }
}
