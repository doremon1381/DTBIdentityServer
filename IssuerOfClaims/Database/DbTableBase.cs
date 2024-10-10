using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Database
{
    public abstract class DbTableBase<TEntity> : IDbContextBase<TEntity> where TEntity : class, IDbTable
    {
        protected IConfigurationManager configuration { get; set; }

        //private delegate void Callback

        protected DbTableBase(IConfigurationManager configuration)
        {
            this.configuration = configuration;
        }

        public DbContextManager CreateDbContext()
        {
            var contextOptions = new DbContextOptionsBuilder<DbContextManager>()
                 .UseSqlServer(this.configuration.GetConnectionString(DbUltilities.DatabaseName))
                 .Options;

            var dbContext = new DbContextManager(contextOptions, null);
            return dbContext;
        }

        /// <summary>
        /// TODO: for now, Savechanges() is automatically used after callback, will check it late
        /// </summary>
        /// <param name="callback"></param>
        public void UsingDbSetWithSaveChanges(Action<DbSet<TEntity>> callback)
        {
            using (var dbContext = CreateDbContext())
            {
                var dbSet = dbContext.GetDbSet<TEntity>();
                callback(dbSet);

                dbContext.SaveChanges();
            }
        }

        public void UsingDbSet(Action<DbSet<TEntity>> callback)
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

        public void UsingDbContext(Action<DbContextManager> callback)
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
                UsingDbContext((dbContext) =>
                {
                    var dbSet = dbContext.GetDbSet<TEntity>();
                    dbSet.Add(model);

                    dbContext.SaveChanges();
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
                using (var dbContext = this.CreateDbContext())
                {
                    var dbModels = dbContext.GetDbSet<TEntity>();

                    dbModels.Update(model);
                    dbContext.SaveChanges();
                }

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

        public virtual bool AddMany(List<TEntity> models)
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

        public void ValidateEntity(TEntity obj, string message = "")
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
        void ValidateEntity(DbModel obj, string message = "");
    }
}
