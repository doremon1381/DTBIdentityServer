using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;

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
            using (var scope = serviceProvider.CreateAsyncScope())
            {
                using (var context = serviceProvider.GetService<DbContextManager>())
                {
                    try
                    {
                        var databaseIsExist = (context.Database.GetService<IDatabaseCreator>() as RelationalDatabaseCreator).Exists();

                        if (!databaseIsExist)
                        {
                            context.Database.EnsureCreated();
                            // TODO: use for initiate clients in database
                            AuthorizationResources.CreateClient(context);
                        }

                        // call ef core to apply migration at application startup
                        context.Database.Migrate();
                    }
                    catch (Exception ex)
                    {
                        var logger = serviceProvider.GetRequiredService<ILogger>();
                        logger.LogError(ex, "An error occured while migrate database!");

                        throw;
                    }
                }

            }

            return builder;
        }
    }
}
