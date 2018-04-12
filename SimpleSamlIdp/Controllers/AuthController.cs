using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Mvc;
using ITfoxtec.Identity.Saml2.Schemas;
using SimpleSamlIdp.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.Mvc;

namespace SimpleSamlIdp.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso cref="System.Web.Mvc.Controller" />
    public class AuthController : Controller
    {
        /// <summary>
        /// Parses the specified delimited Key=value string.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="delimiter">The delimiter.</param>
        /// <returns></returns>
        private static List<string> Parse(string data, string delimiter)
        {
            if (data == null) return null;
            if (!delimiter.EndsWith("=")) delimiter = delimiter + "=";
            if (!data.Contains(delimiter)) return null;
            //base case
            var result = new List<string>();
            int start = data.IndexOf(delimiter) + delimiter.Length;
            int length = data.IndexOf(',', start) - start;
            if (length == 0) return null; //the group is empty
            if (length > 0)
            {
                result.Add(data.Substring(start, length));
                //only need to recurse when the comma was found, because there could be more groups
                var rec = Parse(data.Substring(start + length), delimiter);
                if (rec != null) result.AddRange(rec); //can't pass null into AddRange() :(
            }
            else //no comma found after current group so just use the whole remaining string
            {
                result.Add(data.Substring(start));
            }
            return result;
        }

        public static X509Certificate2 GetIssuer(X509Certificate2 leafCert)
        {
            if (leafCert.Subject == leafCert.Issuer) { return leafCert; }
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.Build(leafCert);
            X509Certificate2 issuer = null;
            if (chain.ChainElements.Count > 1)
            {
                issuer = chain.ChainElements[1].Certificate;
            }
            chain.Reset();
            return issuer;
        }


        private IEnumerable<Claim> GetClaimsFromCertificate( HttpClientCertificate cert)
        {
            //Validate cert
            var x509Issuer = GetIssuer(new X509Certificate2(cert.Certificate));

            if (ValidateIssuer(x509Issuer))
            {
                return ExtractUserClaims(cert.Subject);
            } else
            {
                throw new CryptographicException("Issuer is not trusted");
            }
        }


        /// <summary>
        /// The relay state return URL
        /// </summary>
        const string relayStateReturnUrl = "ReturnUrl";

        /// <summary>
        /// Gets the security algorithms.
        /// </summary>
        /// <value>
        /// The security algorithms.
        /// </value>
        public object SecurityAlgorithms { get; private set; }

        /// <summary>
        /// The configuration
        /// </summary>
        private readonly SamlConfiguration config;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthController"/> class.
        /// </summary>
        public AuthController()
        {
            config = IdentityConfig.samlConfiguration;
        }


        // GET: Auth
        /// <summary>
        /// Indexes this instance.
        /// </summary>
        /// <returns></returns>
        public ActionResult Index()
        {
            var claims = GetClaimsFromCertificate(this.Request.ClientCertificate);
            ViewBag.Claims = claims;
            return View();
        }

        /// <summary>
        /// Posts this instance.
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("Login")]
        public ActionResult Post()
        {
            var requestBinding = new Saml2PostBinding();
            var relyingParty = ValidateRelyingParty(ReadRelyingPartyFromLoginRequest(requestBinding));

            var saml2AuthnRequest = new Saml2AuthnRequest(config.IDP);
            try
            {
                requestBinding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnRequest);

                // ****  Handle user login e.g. in GUI ****
                // Test user with session index and claims
                var sessionIndex = Guid.NewGuid().ToString();

                var claims = GetClaimsFromCertificate(this.Request.ClientCertificate);

                return LoginResponse(saml2AuthnRequest.Id, Saml2StatusCodes.Success, requestBinding.RelayState, relyingParty, sessionIndex, claims);
            }
            catch (Exception exc)
            {
                return LoginResponse(saml2AuthnRequest.Id, Saml2StatusCodes.Responder, requestBinding.RelayState, relyingParty);
            }
        }

        /// <summary>
        /// Redirects this instance.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("Login")]
        public ActionResult Redirect()
        {
            var requestBinding = new Saml2RedirectBinding();
            var relyingParty = ValidateRelyingParty(ReadRelyingPartyFromLoginRequest(requestBinding));

            var saml2AuthnRequest = new Saml2AuthnRequest(config.IDP);
            try
            {
                requestBinding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnRequest);

                // ****  Handle user login e.g. in GUI ****
                // Test user with session index and claims
                var sessionIndex = Guid.NewGuid().ToString();

                var claims = GetClaimsFromCertificate(this.Request.ClientCertificate);

                return LoginResponse(saml2AuthnRequest.Id, Saml2StatusCodes.Success, requestBinding.RelayState, relyingParty, sessionIndex, claims);
            }
            catch (Exception exc)
            {
                return LoginResponse(saml2AuthnRequest.Id, Saml2StatusCodes.Responder, requestBinding.RelayState, relyingParty);
            }
        }

        /// <summary>
        /// Reads the relying party from login request.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="binding">The binding.</param>
        /// <returns></returns>
        private Uri ReadRelyingPartyFromLoginRequest<T>(Saml2Binding<T> binding)
        {
            return binding.ReadSamlRequest(Request.ToGenericHttpRequest(), new Saml2AuthnRequest(config.IDP))?.Issuer;
        }

        /// <summary>
        /// Logins the response.
        /// </summary>
        /// <param name="inResponseTo">The in response to.</param>
        /// <param name="status">The status.</param>
        /// <param name="relayState">State of the relay.</param>
        /// <param name="relyingParty">The relying party.</param>
        /// <param name="sessionIndex">Index of the session.</param>
        /// <param name="claims">The claims.</param>
        /// <returns></returns>
        private ActionResult LoginResponse(Saml2Id inResponseTo, Saml2StatusCodes status, string relayState, Saml2Configuration relyingParty, string sessionIndex = null, IEnumerable<Claim> claims = null)
        {
            var responsebinding = new Saml2PostBinding();
            responsebinding.RelayState = relayState;

            var saml2AuthnResponse = new Saml2AuthnResponse(config.IDP)
            {
                InResponseTo = inResponseTo,
                Status = status,
                Destination = relyingParty.SingleSignOnDestination,
            };
            if (status == Saml2StatusCodes.Success && claims != null)
            {
                saml2AuthnResponse.SessionIndex = sessionIndex;

                var claimsIdentity = new ClaimsIdentity(claims);
                saml2AuthnResponse.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single(), NameIdentifierFormats.Persistent);
                saml2AuthnResponse.ClaimsIdentity = claimsIdentity;

                var token = saml2AuthnResponse.CreateSecurityToken(relyingParty.Issuer);
            }

            return responsebinding.Bind(saml2AuthnResponse).ToActionResult();
        }


        /// <summary>
        /// Validates the relying party.
        /// </summary>
        /// <param name="issuer">The issuer.</param>
        /// <returns></returns>
        private Saml2Configuration ValidateRelyingParty(Uri issuer)
        {
            var validRelyingPartys = config.RP;
            return validRelyingPartys.Where(rp => rp.Issuer.OriginalString.Equals(issuer.OriginalString, StringComparison.InvariantCultureIgnoreCase)).Single();
        }

        /// <summary>
        /// Validates the issuer of teh client certificate.
        /// </summary>
        /// <param name="issuer">The issuer.</param>
        /// <returns></returns>
        private bool ValidateIssuer(X509Certificate2 issuer)
        {
            var validIssuerSerialnumbers = config.ClientCertificateIssuers;
            if (validIssuerSerialnumbers.Count == 0) return true;
            return validIssuerSerialnumbers.Where(iss => iss.Equals(issuer.GetSerialNumberString(), StringComparison.InvariantCultureIgnoreCase)).Count()==1;
        }


        /// <summary>
        /// Extracts the user claims.
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <returns></returns>
        private IEnumerable<Claim> ExtractUserClaims(string subject)
        {
            string cn = Parse(subject, "CN").FirstOrDefault();
            string email = Parse(subject, "E").FirstOrDefault();
            string surname = Parse(subject, "SN").FirstOrDefault();
            string given = Parse(subject, "G").FirstOrDefault();

            yield return new Claim(ClaimTypes.NameIdentifier, cn);
            yield return new Claim(ClaimTypes.Email, email);
            yield return new Claim(ClaimTypes.GivenName, given);
            yield return new Claim(ClaimTypes.Surname, surname);
        }

    }
}