using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public abstract class DbTableServicesBase<TEntity> : IDbContextBase<TEntity> where TEntity : class, IDbTable
    {
        private static string? _ConnectionString;

        static DbTableServicesBase()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Environment.CurrentDirectory)
                .AddJsonFile($"appsettings.json").Build();
            _ConnectionString = builder.GetConnectionString(DbUtilities.DatabasePath);
        }

        private static DbContextManager CreateDbContext()
        {
            var contextOptions = new DbContextOptionsBuilder<DbContextManager>()
                 .UseSqlServer(_ConnectionString)
                 .Options;

            var dbContext = new DbContextManager(contextOptions, null);
            return dbContext;
        }

        internal static Func<DbContextManager, IEnumerable<TEntity>> CompileDynamicQuery(Func<DbSet<TEntity>, IQueryable<TEntity>> query)
        {
            return EF.CompileQuery((DbContextManager dbcontext) => query(dbcontext.GetDbSet<TEntity>()));
        }

        /// <summary>
        /// TODO: for now, Savechanges() is automatically used after callback, will check it late
        /// </summary>
        /// <param name="callback"></param>
        internal static void UsingDbSetWithSaveChanges(Action<DbSet<TEntity>> callback)
        {
            using (var dbContext = CreateDbContext())
            {
                var dbSet = dbContext.GetDbSet<TEntity>();
                callback(dbSet);

                dbContext.SaveChanges();
            }
        }

        internal static async Task UsingDbSetAsync(Action<DbSet<TEntity>> callback)
        {
            await TaskUtilities.RunAttachedToParentTask(() =>
            {
                using (var dbContext = CreateDbContext())
                {
                    var dbSet = dbContext.GetDbSet<TEntity>();
                    callback(dbSet);
                }
            });
            // TODO: will think about it later
            //await task.ContinueWith(t =>
            //{
            //    if (t.IsFaulted)
            //    {
            //        throw new CustomException("Something is wrong while using dbset!");
            //    }
            //}, TaskContinuationOptions.OnlyOnFaulted);

        }

        // TODO: will add dynamic building include query, 
        //     : will add dynamic building query for get object or get range of objects
        //public TEntity GetObject(bool isValidate)
        //{
        //    using (var dbContext = CreateDbContext())
        //    {
        //        var dbSet = dbContext.GetDbSet<TEntity>();
        //        callback(dbSet);
        //    }
        //}

        internal static async Task UsingDbContextAsync(Action<DbContextManager> callback)
        {
            await TaskUtilities.RunAttachedToParentTask(() =>
            {
                using (var dbContext = CreateDbContext())
                {
                    callback(dbContext);
                }
            });
        }

        public List<TEntity> GetAll()
        {
            List<TEntity> temp = new List<TEntity>();

            UsingDbSetWithSaveChanges((dbSet) =>
            {
                temp.AddRange(dbSet.ToList());
            });

            return temp;
        }

        public bool Create(TEntity model)
        {
            try
            {
                UsingDbSetWithSaveChanges((dbSet) =>
                {
                    dbSet.Add(model);
                });
            }
            catch (Exception)
            {
                //return false;
                throw;
            }

            return true;
        }

        public bool Update(TEntity model)
        {
            try
            {
                UsingDbSetWithSaveChanges(dbModels =>
                {
                    dbModels.Update(model);
                });

            }
            catch (Exception)
            {
                //return false;
                throw;
            }

            return true;
        }

        public bool Delete(TEntity model)
        {
            try
            {
                UsingDbSetWithSaveChanges((dbSet) =>
                {
                    dbSet.Remove(model);
                });
            }
            catch (Exception)
            {
                //return false;
                throw;
            }

            return true;
        }

        public async Task<bool> IsTableEmptyAsync()
        {
            bool isEmpty = true;

            await UsingDbSetAsync((dbSet) =>
            {
                isEmpty = !(dbSet.Count() > 0);
            });

            return isEmpty;
        }

        public bool AddMany(List<TEntity> models)
        {
            bool hasError = false;
            try
            {
                UsingDbSetWithSaveChanges((dbSet) =>
                {
                    dbSet.AddRange(models);
                });
            }
            catch (Exception ex)
            {
                // TODO:
                hasError = true;
                throw;
            }

            return !hasError;
        }

        public static void ValidateEntity(TEntity obj, HttpStatusCode statusCode, string message = "")
        {
            if (obj == null)
                throw new CustomException(message, statusCode);
        }
    }

    /// <summary>
    /// CRUD & something
    /// </summary>
    public interface IDbContextBase<DbModel> where DbModel : class, IDbTable
    {
        Task<bool> IsTableEmptyAsync();
        List<DbModel> GetAll();
        bool Create(DbModel model);
        //bool Add(TDbModel model);
        bool Update(DbModel model);
        bool Delete(DbModel model);
        bool AddMany(List<DbModel> models);
    }
}
