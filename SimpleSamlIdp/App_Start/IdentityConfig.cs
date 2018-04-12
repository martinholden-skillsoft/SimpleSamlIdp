using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using ITfoxtec.Identity.Saml2.Util;
using SimpleSamlIdp.Models;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Claims;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Web;
using System.Web.Helpers;
using System.Web.Hosting;

namespace SimpleSamlIdp
{
    public static class IdentityConfig
    {
        public static SamlConfiguration samlConfiguration { get; private set; } = new SamlConfiguration();

        public static void RegisterIdentity()
        {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;

            samlConfiguration.IDP.Issuer = new Uri(ConfigurationManager.AppSettings["Saml2IDP:Issuer"]);

            samlConfiguration.IDP.SingleSignOnDestination = new Uri(ConfigurationManager.AppSettings["Saml2IDP:SingleSignOnDestination"], UriKind.RelativeOrAbsolute);
            //Saml2Configuration.SingleLogoutDestination = new Uri(ConfigurationManager.AppSettings["Saml2IDP:SingleLogoutDestination"]);

            samlConfiguration.IDP.SignatureAlgorithm = ConfigurationManager.AppSettings["Saml2IDP:SignatureAlgorithm"];
            //samlConfiguration.IDP.SigningCertificate = CertificateUtil.Load(HttpContext.Current.Server.MapPath(ConfigurationManager.AppSettings["Saml2IDP:SigningCertificateFile"]), ConfigurationManager.AppSettings["Saml2IDP:SigningCertificatePassword"]);
            try
            {
                samlConfiguration.IDP.SigningCertificate = CertificateUtil.Load(HostingEnvironment.MapPath(ConfigurationManager.AppSettings["Saml2IDP:SigningCertificateFile"]), ConfigurationManager.AppSettings["Saml2IDP:SigningCertificatePassword"]);
            }
            catch (Exception ex)
            {
                throw new Exception("Cant find " + HostingEnvironment.MapPath(ConfigurationManager.AppSettings["Saml2IDP:SigningCertificateFile"]));
            }
            samlConfiguration.IDP.CertificateValidationMode = (X509CertificateValidationMode)Enum.Parse(typeof(X509CertificateValidationMode), ConfigurationManager.AppSettings["Saml2IDP:CertificateValidationMode"]);
            samlConfiguration.IDP.RevocationMode = (X509RevocationMode)Enum.Parse(typeof(X509RevocationMode), ConfigurationManager.AppSettings["Saml2IDP:RevocationMode"]);

            samlConfiguration.IDP.AllowedAudienceUris.Add(samlConfiguration.IDP.Issuer);

            List<string> RP = new List<string>(ConfigurationManager.AppSettings["Saml2IDP:RP"].Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries));
            foreach (var item in RP)
            {
                var data = item.Split(new char[] { '|' });
                samlConfiguration.RP.Add(new Saml2Configuration() { Issuer = new Uri(data[0]), SingleSignOnDestination = new Uri(data[1]) });
            }

            samlConfiguration.ClientCertificateIssuers = new List<string>(ConfigurationManager.AppSettings["Saml2IDP:ClientCertificateIssuerSerialNumber"].Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries));


        }
    }
}