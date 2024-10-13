using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Database
{
    public abstract class DbTableBase<TEntity> : IDbContextBase<TEntity> where TEntity : class, IDbTable
    {
        private static string? _ConnectionString;

        static DbTableBase()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Environment.CurrentDirectory)
                .AddJsonFile($"appsettings.json").Build();
            _ConnectionString = builder.GetConnectionString(DbUtilities.DatabaseName);
        }

        public static DbContextManager CreateDbContext()
        {
            var contextOptions = new DbContextOptionsBuilder<DbContextManager>()
                 .UseSqlServer(_ConnectionString)
                 .Options;

            var dbContext = new DbContextManager(contextOptions, null);
            return dbContext;
        }

        /// <summary>
        /// TODO: for now, Savechanges() is automatically used after callback, will check it late
        /// </summary>
        /// <param name="callback"></param>
        public static void UsingDbSetWithSaveChanges(Action<DbSet<TEntity>> callback)
        {
            using (var dbContext = CreateDbContext())
            {
                var dbSet = dbContext.GetDbSet<TEntity>();
                callback(dbSet);

                dbContext.SaveChanges();
            }
        }

        public static void UsingDbSet(Action<DbSet<TEntity>> callback)
        {
            using (var dbContext = CreateDbContext())
            {
                var dbSet = dbContext.GetDbSet<TEntity>();
                callback(dbSet);
            }
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

        public static void UsingDbContext(Action<DbContextManager> callback)
        {
            using (var dbContext = CreateDbContext())
            {
                callback(dbContext);
            }
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

        //public bool Add(TEntity model)
        //{
        //    try
        //    {
        //        this._DbModels.Add(model);
        //        this.SaveChanges();
        //    }
        //    catch (Exception)
        //    {
        //        //return false;
        //        throw;
        //    }

        //    return true;
        //}

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
        public bool IsTableEmpty()
        {
            bool isEmpty = true;

            using (var dbContext = CreateDbContext())
            {
                var dbSet = dbContext.GetDbSet<TEntity>();
                isEmpty = !(dbSet.Count() > 0);
            }

            return isEmpty;
        }

        public bool AddMany(List<TEntity> models)
        {
            bool hasError = false;
            try
            {
                using (var dbContext = CreateDbContext())
                {
                    var dbSet = dbContext.GetDbSet<TEntity>();
                    dbSet.AddRange(models);

                    dbContext.SaveChanges();
                }
            }
            catch (System.Exception ex)
            {
                // TODO:
                hasError = true;
                throw;
            }

            return !hasError;
        }

        public static void ValidateEntity(TEntity obj, string message = "")
        {
            if (obj == null)
                throw new InvalidOperationException(message);
        }
    }

    /// <summary>
    /// CRUD & something
    /// </summary>
    public interface IDbContextBase<DbModel> where DbModel : class, IDbTable
    {
        bool IsTableEmpty();
        List<DbModel> GetAll();
        bool Create(DbModel model);
        //bool Add(TDbModel model);
        bool Update(DbModel model);
        bool Delete(DbModel model);
        bool AddMany(List<DbModel> models);
    }
}
