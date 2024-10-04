using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using ServerDbModels;

namespace IssuerOfClaims.Database
{
    public abstract class DbTableBase<TEntity> : IDbContextBase<TEntity> where TEntity : class, IDbTable
    {
        protected IConfigurationManager configuration { get; set; }

        protected DbTableBase(IConfigurationManager configuration)
        {
            this.configuration = configuration;
        }

        public DbContextManager CreateDbContext(IConfigurationManager configuration)
        {
            var contextOptions = new DbContextOptionsBuilder<DbContextManager>()
                 .UseSqlServer(configuration.GetConnectionString(DbUltilities.DatabaseName))
                 .Options;

            var dbContext = new DbContextManager(contextOptions, null);
            return dbContext;
        }

        public List<TEntity> GetAll()
        {
            List<TEntity> temp = new List<TEntity>();

            using (var dbContext = CreateDbContext(configuration))
            {
                var dbSet = dbContext.GetDbSet<TEntity>();
                temp.AddRange(dbSet.ToList());
            }

            return temp;
        }

        public bool Create(TEntity model)
        {
            try
            {
                using (var dbContext = CreateDbContext(configuration))
                {
                    var dbSet = dbContext.GetDbSet<TEntity>();
                    dbSet.Add(model);

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
                using (var dbContext = this.CreateDbContext(configuration))
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
                using (var dbContext = CreateDbContext(configuration))
                {
                    var dbSet = dbContext.GetDbSet<TEntity>();
                    dbSet.Remove(model);

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
        public bool IsTableEmpty()
        {
            bool isEmpty = true;

            using (var dbContext = CreateDbContext(configuration))
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
                using (var dbContext = CreateDbContext(configuration))
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
