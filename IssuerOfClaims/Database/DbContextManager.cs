using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using ServerDbModels;
using System.Reflection;

namespace IssuerOfClaims.Database
{
    public class DbContextManager : DbContext, IDbContextManager
    {

        private ILogger<DbContextManager> _logger;
        //private DbContextOptions _options;
        //private IConfiguration _configuration;

        #region DbSet needs to be add in this DbContext to prevent an error of DbSet is not existed in this context (I think it means in this DbContext class) when using later
        //public DbSet<UserIdentity> Users { get; set; }
        //public DbSet<Role> Roles { get; set; }
        //public DbSet<IdentityUserRole> IdentityUserRoles { get; set; }
        //public DbSet<Client> Clients { get; set; }
        //public DbSet<ConfirmEmail> ConfirmEmails { get; set; }
        //public DbSet<TokenResponsePerIdentityRequest> TokenResponsePerHandlers { get; set; }
        //public DbSet<TokenRequestSession> TokenRequestSessions { get; set; }
        //public DbSet<TokenRequestHandler> TokenRequestHandlers { get; set; }
        //public DbSet<TokenResponse> TokenResponses { get; set; }
        //public DbSet<IdToken> IdTokens { get; set; }
        #endregion

        public DbContextManager(DbContextOptions<DbContextManager> options, ILogger<DbContextManager> logger)
            : base(options)
        {
            //_options = options;
            _logger = logger;

            //_configuration = configuration;

        }

        public void DbSaveChanges()
        {
            this.SaveChanges();
        }

        public DbSet<TEntity> GetDbSet<TEntity>() where TEntity : class
        {
            if (typeof(IDbTable).IsAssignableFrom(typeof(TEntity)))
            {
                return this.Set<TEntity>();
            }

            // TODO: for learning
            _logger.LogInformation($"GetDbSet is called!");
            // TODO: will change 
            return null;
        }

        // Using Type: 5.0.16.0  EntityFrameworkCore.DbContext (confirm if working with any core library upgrades)

        public bool IsDisposed()
        {
            bool result = true;
            var typeDbContext = typeof(DbContext);
            var isDisposedTypeField = typeDbContext.GetField("_disposed", BindingFlags.NonPublic | BindingFlags.Instance);

            if (isDisposedTypeField != null)
            {
                result = (bool)isDisposedTypeField.GetValue(this);
            }

            return result;
        }

#if (DEBUG || RELEASE)
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Client>()
                .HasMany(c => c.TokenRequestSession)
                .WithOne(l => l.Client)
                .HasForeignKey(c => c.ClientId);

            modelBuilder.Entity<TokenRequestHandler>()
                .HasOne(c => c.TokenRequestSession)
                .WithOne(l => l.TokenRequestHandler)
                .HasForeignKey<TokenRequestSession>(l => l.TokenRequestHandlerId);

            modelBuilder.Entity<TokenRequestHandler>()
                .HasMany(c => c.TokenResponsePerHandlers)
                .WithOne(t => t.TokenRequestHandler)
                .HasForeignKey(c => c.TokenRequestHandlerId);

            base.OnModelCreating(modelBuilder);
        }
#else 
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlServer("Server=DESKTOP-2TRDKFE\\;Database=LAuthentication;trusted_connection=true;TrustServerCertificate=True");
            base.OnConfiguring(optionsBuilder);
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            //modelBuilder.Entity<CustomClient>()
            //    .Property(x => x.Properties)
            //    .HasConversion(
            //        x => JsonConvert.SerializeObject(x),
            //        x => JsonConvert.DeserializeObject<IDictionary<string, string>>(x));
            //        // TODO: need to learn about compare
            //        new ValueComparer<IDictionary<string, string>>(
            //            (c1, c2) => c1.SequenceEqual(c2),
            //            c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
            //            c => c.ToDictionary<string,string>()));
            base.OnModelCreating(modelBuilder);
        }
#endif
    }

    public interface IDbContextManager
    {
        void DbSaveChanges();
        bool IsDisposed();
        DbSet<TEntity> GetDbSet<TEntity>() where TEntity : class;
    }

    // TODO: for migration
    public class YourDbContextFactory : IDesignTimeDbContextFactory<DbContextManager>
    {
        public DbContextManager CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<DbContextManager>();
            optionsBuilder.UseSqlServer("Server=DESKTOP-2TRDKFE\\;Database=PrintingManagermentIdentity;trusted_connection=true;TrustServerCertificate=True");

            // TODO: logger as parameter is null for now
            return new DbContextManager(optionsBuilder.Options, null);
        }
    }
}
