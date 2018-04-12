# SimpleSamlIdp

## Preparations
The steps are:
1. [Generate Certificates](#generate-certificates)
2. [Host Setup](#host-setup) - configuration of IIS or IIS Express for Client Certificates
3. [Application Setup](#application-setup) - configuration of the application via web.config


### [Generate Certificates](#generate-certificates)
The first step for using this solution is to generate the necessary Self Signed X509 certificates.

These instructions will use Windows commands, during each step you will be asked to specify passwords to secure the certificates - MAKE A NOTE OF THESE

#### RootCA
~~~
makecert.exe -n "CN=MyCompanyRootCA,OU=Testing,O=MyCompany,C=GB" -r -pe -a sha512 -len 4096 -cy authority -sv MyCompanyCA.pvk MyCompanyCA.cer
pvk2pfx.exe -pvk MyCompanyCA.pvk -spc MyCompanyCA.cer -pfx MyCompanyCA.pfx
~~~

Once generated you should install the MyCompanyCA.CER file into the Local Machine Certificate Store in the Trusted Root Folder.

1. Run MMC
2. Open the Certificate Manager (certmgr.msc in C:\Windows\System32)
3. You will see it opens 'Certificates - Current User'
4. In the menu, choose File, Add/Remove Snap-In
5. Now press Add, select 'Certificates' and select 'Computer Account'
5. Select the Local Computer
6. Now you have two snap-ins: Certificates - Current User & Certificates (Local Computer)
8. Now import the certificate in "Certificates (Local Computer)\Trusted Root Certificates\Certificates"

#### SAML Signing
~~~
makecert.exe -n "CN=urn:martinholden:identity:saml2:simplesamlidp" -r -pe -a sha512 -len 4096 -cy authority -sv saml_signing.pvk saml_signing.cer
pvk2pfx.exe -pvk saml_signing.pvk -spc saml_signing.cer -pfx saml_signing.pfx
~~~
Replace the urn:martinholden:identity:saml2:simplesamlidp with your chosen entityid, update the web.config value with your new entityid (Saml2IDP:Issuer)

Once generated you will need to place the saml_signing.pfx file in the App_Data folder of the solution, mark as Content and Copy Always in the properties and update the web.config with the appropriate filename (Saml2IDP:SigningCertificateFile) and password (Saml2IDP:SigningCertificatePassword).

[web.config](https://github.com/martinholden-skillsoft/SimpleSamlIdp/blob/master/SimpleSamlIdp/Web.config)

#### User Certificates
~~~
makecert.exe -n "CN=username,SN=Surname,G=Givenname,E=user@mycompany.com,OU=Testing,O=MyCompany,C=GB" -iv MyCompanyCA.pvk -ic MyCompanyCA.cer -pe -a sha512 -len 4096 -sky exchange -eku 1.3.6.1.5.5.7.3.2 -sv myuser.pvk myuser.cer
pvk2pfx.exe -pvk myuser.pvk -spc myuser.cer -pfx myuser.pfx
~~~
Replace the values for the username with the appropriate data.

Once generated you should install the myuser.pfx file into your user certificate store in the Personal folder on your Client Machine NOT the IIS machine.

1. Double-click the PFX
2. Accept the defaults in the Windows Certificate Import, enter your password.

You can generate and install as many of these as you like - just remember to update the user info and the cert filenames.

## [Host Setup](#host-setup)

### Configuring IIS to allow Certificate Selection

You may need to make a registry change to ensure you can select which certificate to present.

On the server that is running IIS, set the following registry entry to false: 

~~~
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL

Value name: SendTrustedIssuerList
Value type: REG_DWORD
Value data: 0 (False)
~~~

By default, this entry is not listed in the registry. By default, this value is 1 (True). This registry entry controls the flag that controls whether the server sends a list of trusted certificate authorities to the client. When you set this registry entry to False, the server does not send a list of trusted certificate authorities to the client. This behavior may affect how the client responds to a request for a certificate. For example, if Internet Explorer receives a request for client authentication, Internet Explorer displays only the client certificates that appear in the chain of one of the certification authorities that are in the list from the server. However, if the server does not send a list of trusted certificate authorities, Internet Explorer displays all the client certificates that are installed on the client computer. 

### Configuring IIS to enable reading of PFX file

On IIS running when the application is running on the DefaultAppPool it may fail to read the SAML Signing certificate in the App_Data folder.

To fix this the user profile needs to be loaded for the Application Pool Identity.

The configuration setting that governs whether the user profile is loaded for the Application Pool identity is loadUserProfile, which is set to false, by default.

You can configure this setting by changing the value of the Load User Profile attribute in the Advanced Settings dialog box for an application pool in IIS.

You can also configure this setting by using the command-line tool AppCmd.exe with the following syntax:
~~~
appcmd.exe set config -section:system.applicationHost/applicationPools /[name='DefaultAppPool'].processModel.loadUserProfile:"True" /commit:apphost
~~~

### Configuring IIS to enable Certificate Authentication on selected routes via Web.config

1. Navigate to the IIS Configuration Manager
2. Locate the access section under Security
3. Click the unlock section link so that it changes to "lock section". The access section is now unlocked and can be overridden at the application level. 

[http://dcdevs.blogspot.co.uk/2017/06/aspnet-mvc-how-to-enabledisable_19.html](http://dcdevs.blogspot.co.uk/2017/06/aspnet-mvc-how-to-enabledisable_19.html)

### Configuring IISExpress Development Server to enable Certificate Authentication on selected routes via Web.config

Open the .vs\config\applicationhost.config file.

Find the section element:
~~~
<section name="access" overrideModeDefault="Deny" />
~~~

Change to:
~~~
<section name="access" overrideModeDefault="Allow" />
~~~

## [Application Setup](#application-setup)
### Web.Config Setup

The final step is configuring the [web.config](https://github.com/martinholden-skillsoft/SimpleSamlIdp/blob/master/SimpleSamlIdp/Web.config) there are a number of app settings.

~~~
 <appSettings>
    <!-- This is the SAML EntityID -->
    <add key="Saml2IDP:Issuer" value="urn:martinholden:identity:saml2:simplesamlidp" />
    <add key="Saml2IDP:SingleSignOnDestination" value="/Auth/Post" />
    <add key="Saml2IDP:SignatureAlgorithm" value="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
    <add key="Saml2IDP:SigningCertificateFile" value="~/App_Data/saml_signing.pfx" />
    <add key="Saml2IDP:SigningCertificatePassword" value="GXTDDF89qHvezFmN" />
    <add key="Saml2IDP:CertificateValidationMode" value="ChainTrust" />
    <add key="Saml2IDP:RevocationMode" value="NoCheck" />

    <!-- Semi-colon delimited list of ENTITYID|ACS URL for the RelyingParties-->
    <add key="Saml2IDP:RP" value="https://sso.skillport.com|https://sso.skillport.com/sp/ACS.saml2" />

    <!-- Semi-colon delimited list of Issuer Serial Numbers for the client certificates - leave blank for no validation -->
    <add key="Saml2IDP:ClientCertificateIssuerSerialNumber" value="‎215113C1F3E8618F49DDD8638647DAA6;" />
  </appSettings>
~~~

You should set:
1. Saml2IDP:Issuer - This is your unique SAML EntityID for this Identity provider
2. Saml2IDP:SigningCertificateFile - This is the path to the password protected PFX file that contains your SAML Signing certificate and Private Key
3. Saml2IDP:SigningCertificatePassword - This is the password for the PFX
4. Saml2IDP:RP - This is a semi-colon delimited list of RelyingParty information. Each value is the RP ENTYITYID|RP ACS URL
5. Saml2IDP:ClientCertificateIssuerSerialNumber -  This is a semi-colon delimted list of the serial number (uppercase) of the Client Certificate Issuers.  If you are creating self-signing certificates as above this will be the Serial Number of the MyCompanyRootCA. If you leave blank any certificate that is TRUSTED by the Root Certificates on the machine can be used.







