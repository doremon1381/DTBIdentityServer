using IssuerOfClaims.Extensions;

namespace IssuerOfClaims.Services
{
    public class LazyService<T> where T: class
    {
        private T? _service = null;
        public T Service 
        {
            get
            {
                return _serviceProvider.GetServiceLazily(ref _service);
            }
            private set 
            {
                _service = value;
            } 
        }

        private IServiceProvider _serviceProvider;

        public LazyService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

    }

    public interface IlazyService<T>
    {
    }
}
