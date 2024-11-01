using Microsoft.AspNetCore.Mvc;
using static ServerUltilities.Identity.Constants;
using System.Net;
using System.Reflection;
using IssuerOfClaims.Controllers.Ultility;
using Microsoft.AspNetCore.Authorization;
using Newtonsoft.Json;
using static ServerUltilities.Identity.OidcConstants;
using ServerUltilities.Identity;
using System.Net.Http.Headers;
using System.Drawing.Imaging;
using System.Drawing;
using IssuerOfClaims.Extensions;

namespace IssuerOfClaims.Controllers
{
    [ApiController]
    [Route("[controller]")]
    //[ApiVersion("1.0")]
    [ControllerName("")]
    [AllowAnonymous]
    public class DiscoveryController : ControllerBase
    {
        private static readonly List<FieldInfo> _EndpointNames = typeof(EndpointNames).GetFields(BindingFlags.Public | BindingFlags.Static).ToList();
        private static readonly List<FieldInfo> _ProtocolRoutePaths = typeof(ProtocolRoutePaths).GetFields(BindingFlags.Public | BindingFlags.Static).ToList();
        private static readonly List<FieldInfo> _StandardScopes = typeof(StandardScopes).GetFields(BindingFlags.Public | BindingFlags.Static).ToList();

        private static string discoveryString = string.Empty;
        private static readonly Image favicon = Utilities.ResizeImageToBitmap(32, 32, $"{Environment.CurrentDirectory}\\Img\\himeko.jpg");

        public DiscoveryController()
        {

        }

        [HttpGet("favicon.ico")]
        public async Task FavicoEndpoint()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                favicon.Save(ms, ImageFormat.Bmp);

                await HttpContext.Response.Body.WriteAsync(ms.ToArray(), 0, (int)ms.Length);
            }
        }

        #region endpoint discovery
        /// <summary>
        /// https://openid.net/specs/openid-connect-discovery-1_0.html
        /// <para>Intend to ignore "2. OpenID Provider Issuer Discovery"</para>
        /// </summary>
        /// <returns></returns>
        [HttpGet(".well-known/openid-configuration")]
        public ActionResult EndpointDiscovery()
        {
            if (string.IsNullOrEmpty(discoveryString))
            {
                var serverHostUrl = $"{Request.Scheme}://{Request.Host.Value}";
                Dictionary<string, object> discovery = new Dictionary<string, object>();

                // TODO: Discovery + ProtocolRoutePaths
                discovery.Add(Discovery.Issuer, serverHostUrl);

                // add metadata
                AddDefaultEndpoint(discovery, serverHostUrl);
                AddSupportedResponseTypes(discovery);
                //AddSupportedResponseModes(discovery);
                AddScopesSupport(discovery);
                AddSupportedGrantType(discovery);
                AddSupportedSubjectTypes(discovery);
                AddIdTokenSigningAlgorithmsSupported(discovery);
                //AddIdTokenEncryptionAlgorithmsSupported(discovery);
                //AddIdTokenEncryptionEncValuesSupported(discovery);
                AddTokenEndpointAuthenticationMethodsSupported(discovery);
                AddCodeChallengeMethodsSupported(discovery);
                AddClaimsParameterSupported(discovery);
                AddRequestParameterSupported(discovery);
                AddRequestUriParameterSupported(discovery);

                discoveryString = JsonConvert.SerializeObject(discovery, Formatting.Indented);
            }

            return StatusCode((int)HttpStatusCode.OK, discoveryString);
        }

        private void AddCodeChallengeMethodsSupported(Dictionary<string, object> discovery)
        {
            discovery.Add(Discovery.CodeChallengeMethodsSupported, SupportedCodeChallengeMethods);
        }

        private void AddRequestUriParameterSupported(Dictionary<string, object> discovery)
        {
            discovery.Add(Discovery.RequestUriParameterSupported, false);
        }

        private void AddRequestParameterSupported(Dictionary<string, object> discovery)
        {
            discovery.Add(Discovery.RequestParameterSupported, false);
        }

        private void AddClaimsParameterSupported(Dictionary<string, object> discovery)
        {
            discovery.Add(Discovery.ClaimsParameterSupported, false);
        }

        /// <summary>
        /// TODO: will support another authentication methods in the future
        /// </summary>
        /// <param name="discovery"></param>
        private void AddTokenEndpointAuthenticationMethodsSupported(Dictionary<string, object> discovery)
        {
            discovery.Add(Discovery.TokenEndpointAuthenticationMethodsSupported, new[] {
                EndpointAuthenticationMethods.BasicAuthentication,
                EndpointAuthenticationMethods.PostBody
            });
        }

        private void AddIdTokenEncryptionEncValuesSupported(Dictionary<string, object> discovery)
        {
            throw new NotImplementedException();
        }

        private void AddIdTokenEncryptionAlgorithmsSupported(Dictionary<string, object> discovery)
        {
            throw new NotImplementedException();
        }

        private void AddIdTokenSigningAlgorithmsSupported(Dictionary<string, object> discovery)
        {
            discovery.Add(Discovery.IdTokenSigningAlgorithmsSupported, new[] { Algorithms.Symmetric.HS256, Algorithms.Asymmetric.RS256 });
        }

        private void AddSupportedSubjectTypes(Dictionary<string, object> discovery)
        {
            discovery.Add(Discovery.SubjectTypesSupported, SupportedSubjectTypes);
        }

        // TODO: for now, I dont know what is the form of the response to send to client with query and fragment. Currently, I send to client inside response body
        //     : will change to implement openid specs correctly
        private void AddSupportedResponseModes(Dictionary<string, object> discovery)
        {
            discovery.Add(Discovery.ResponseModesSupported, SupportedResponseModes);
        }

        // TODO: for now, this server only supports authorization code, implicit grant will done in next days
        private void AddSupportedGrantType(Dictionary<string, object> discovery)
        {
            discovery.Add(Discovery.GrantTypesSupported, AllowedGrantTypesForAuthorizeEndpoint);
        }

        /// <summary>
        /// TODO: will support another response type in the future
        /// </summary>
        /// <param name="discovery"></param>
        private void AddSupportedResponseTypes(Dictionary<string, object> discovery)
        {
            discovery.Add(Discovery.ResponseTypesSupported, new[] { ResponseTypes.Code, ResponseTypes.IdToken });
        }

        private static KeyValuePair<string, string> MapEndpointAndRoutePath(string endpoint, string routePath)
        {
            return new KeyValuePair<string, string>(endpoint, routePath);
        }

        private static void AddDefaultEndpoint(Dictionary<string, object> discovery, string serverHostUrl)
        {
            _EndpointNames.ForEach(endpoint =>
            {
                var routePathProperty = _ProtocolRoutePaths.Find(p => p.Name.Equals(endpoint.Name));
                discovery.Add(DiscoveryToEndpointMapping[(string)endpoint.GetValue(_EndpointNames)], $"{serverHostUrl}{(string)routePathProperty.GetValue(_ProtocolRoutePaths)}");
            });
        }

        private void AddScopesSupport(Dictionary<string, object> discovery)
        {
            discovery.Add(Discovery.ScopesSupported, _StandardScopes.Select(field => { return field.GetValue(_StandardScopes); }));
        }
        #endregion
    }
}
