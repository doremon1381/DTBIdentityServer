using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public abstract class DbTableServicesBase<TEntity> : IDbContextBase<TEntity> where TEntity : class, IDbTable
    {
        protected IServiceProvider _ServiceProvider;

        public DbTableServicesBase(IServiceProvider serviceProvider)
        {
            _ServiceProvider = serviceProvider;
        }

        internal static Func<DbContextManager, IEnumerable<TEntity>> CompileDynamicQuery(Func<DbSet<TEntity>, IQueryable<TEntity>> query)
        {
            return EF.CompileQuery((DbContextManager dbcontext) => query(dbcontext.GetDbSet<TEntity>()));
        }

        /// <summary>
        /// TODO: for now, Savechanges() is automatically used after callback, will check it late
        /// </summary>
        /// <param name="callback"></param>
        internal void UsingDbSetWithSaveChanges(Action<DbSet<TEntity>> callback)
        {
            var serviceFactory = _ServiceProvider.GetRequiredService<IServiceScopeFactory>();

            using (var sericeScope = serviceFactory.CreateScope())
            {
                using (var dbContext = sericeScope.ServiceProvider.GetService<DbContextManager>())
                {
                    var dbSet = dbContext.GetDbSet<TEntity>();
                    callback(dbSet);

                    dbContext.SaveChanges();
                }
            }
        }

        internal async Task UsingDbSetAsync(Action<DbSet<TEntity>> callback)
        {
            var serviceFactory = _ServiceProvider.GetRequiredService<IServiceScopeFactory>();
            await TaskUtilities.RunAttachedToParentTask(() =>
            {
                using (var sericeScope = serviceFactory.CreateScope())
                {
                    using (var dbContext = sericeScope.ServiceProvider.GetService<DbContextManager>())
                    {
                        var dbSet = dbContext.GetDbSet<TEntity>();
                        callback(dbSet);
                    }
                }
            });
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

        internal async Task UsingDbContextAsync(Action<DbContextManager> callback)
        {
            var serviceFactory = _ServiceProvider.GetRequiredService<IServiceScopeFactory>();
            await TaskUtilities.RunAttachedToParentTask(() =>
            {
                using (var sericeScope = serviceFactory.CreateScope())
                {
                    using (var dbContext = sericeScope.ServiceProvider.GetService<DbContextManager>())
                    {
                        var dbSet = dbContext.GetDbSet<TEntity>();
                        callback(dbContext);
                    }
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
