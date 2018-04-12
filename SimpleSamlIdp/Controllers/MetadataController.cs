using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Mvc;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mime;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace SimpleSamlIdp.Controllers
{
    public class MetadataController : Controller
    {
        private readonly Saml2Configuration config;

        public MetadataController()
        {
            config = IdentityConfig.samlConfiguration.IDP;
        }

        // GET: Metadata
        [AllowAnonymous]
        [HttpGet]
        public ActionResult Index()
        {

            //Fix up relative URL in web.config to be absolute
            Uri ssoUri = config.SingleSignOnDestination;
            if (!ssoUri.IsAbsoluteUri)
            {
                var url = new UrlHelper(this.ControllerContext.RequestContext);
                ssoUri = new Uri(url.Action("Post", "Auth", null, Request.Url.Scheme));
            }


            var entityDescriptor = new EntityDescriptor(config);
            entityDescriptor.ValidUntil = 365;
            entityDescriptor.IdPSsoDescriptor = new IdPSsoDescriptor
            {
                SigningCertificates = new X509Certificate2[]
                {
                    config.SigningCertificate
                },
                SingleSignOnServices = new SingleSignOnService[]
                {
                    new SingleSignOnService { Binding = ProtocolBindings.HttpPost, Location = ssoUri }
                },

                NameIDFormats = new Uri[] { NameIdentifierFormats.Unspecified },
            };

            return File(Encoding.UTF8.GetBytes(new Saml2Metadata(entityDescriptor).CreateMetadata().ToXml()),
                 "application/samlmetadata+xml",
                  "metadata.xml");

        }
    }
}