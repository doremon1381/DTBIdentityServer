using IssuerOfClaims.Controllers.Ultility;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IssuerOfClaims.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [ControllerName("auth")]
    public class AuthenticationController: ControllerBase
    {
        public AuthenticationController() { }

        #region Login
        [HttpPost("signin")]
        [Authorize]
        public ActionResult SignIn()
        {
            // Get user
            // gather request information, redirect to prompt view if it's need
            return Ok();
        }

        [HttpPost("id")]
        [Authorize]
        public ActionResult SignInCallback()
        {
            return Ok();

        }
        #endregion
        private static string uri = $"https://accounts.google.com" +
            $"/signin/oauth/id?authuser=0" +
            $"&part=AJi8hAMFcTSTm-vGntjaPjAnglUow3ADiAG5hk0yX_kjA9HFrtvs0emFQwWExy-p9QUFy5xNCs7AOCbBuGwGVUanuLtxHq8IoupkK8nSbT-lKzKrEnFZj0gxblh2RfcLdP-8c44o44x6lXGMtH6Mq7_IsftyaKEH9yxd7wHYsrKdwWVKE899tqOh2vaihJMgzdF4j2ROpnAMZvd1VwirWHUdx5AgsdUMh0YhzCHtkvfL6I3jmG4Z-LkxtpztBOhRqz7-Dv9x6546cTH0NbZZY860EEVyNfG7rZ2ruZu9FbP3eGHnPe43g7MqytMUDm1rlnQmzttg5qMJ-w-JDbdt2GX-P45t6a1XGK7-7XpCJKDYlw7MICmIBdTGe7zJ1sisEfgq8khxnIznXxyri8h0fm6y8Ug1CMcxqhuUvSdQiinEhpe8GHQaeyDKq6WjQj15QPWvlXGFD0veRbVWnt5q2Z-9-CQ0GMWldNmjnmh_KOfYYG0G_ghTUCTp3exCrljyJKNI0wG-GStrX8-yRAKzecj62anGbSzLwRW0-b1w6XzEwNngJ-AHu8-OjQa1Tgadb_L_fsBS6DLfCEWLT70whFQZ3YpkRPCOPsiQWCnfP0b7F8oAvIU-rQaz0GrppgUFQGQh6xbJcZ0r2Y-M55m_shl6XeSys_byR2zCudtlh9WSUpPeUHeUux9p82XN2Xsp6BrxhMxLjzKu0ssfXyk3MAgbB_FFrkfAYzvxAF4nnYjp66jneSWrlMBVdGAAEuLPmihKnBIZUtwqPHZ9erVaMhLCcJAlt1DxQdnB2C_r8SYTCSSUWA36yPmlpLZ6imM06jClpePfz-NNluEL6wx2ywdsuXYjPcBTMGh-nN4Tdl5kXWTvodavsxHLOXgL1Qmrtzy_gQBgifDD5gJGpIhXnS5vlXlCh6gJSBHHalmKyukcpY8FO3p-Oy04DYlHg_OQNwUjuNUvxWnKNbvbsPdi5DXE2bBmhECqeVNgUO_haHVjHXjNff_TSRLWJ_zZBW9fuHqrdk6N44y1FvtDP37XKgZCu4pemvib8GXXkyA_OiTI-_dLH-1WvMyncNEM9vlbMEpOGGboWDHraOkayPP93KX83FoIQCV8cz4tTPLDr1HYUyhGZg9DgWE" +
            $"&flowName=GeneralOAuthFlow" +
            $"&as=S1628637618%3A1729242776212909" +
            $"&client_id=558160357396-q5qp0ppf4r5svc0g0smshfs8cdcffkm3.apps.googleusercontent.com" +
            $"&rapt=AEjHL4O502QfcCv_pu9T9F86MMsGDDCljsTDHQcL4K-4pZjNVSNN1gi9YrknjsXGiP12As2LwyIwHMiTsi9ad7GssMoIMmqrZw#";
    }
}
