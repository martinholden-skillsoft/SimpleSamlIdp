using ITfoxtec.Identity.Saml2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace SimpleSamlIdp.Models
{
    public class SamlConfiguration
    {
        public SamlConfiguration()
        {
            RP = new List<Saml2Configuration>();
            IDP = new Saml2Configuration();
            ClientCertificateIssuers = new List<string>();
        }

        public List<Saml2Configuration> RP { get; set; }
        public Saml2Configuration IDP { get; set; }

        public List<string> ClientCertificateIssuers { get; set; }

    }
}