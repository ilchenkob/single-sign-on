using MapleWebsite.SingleSignOn.Models;
using MapleWebsite.SingleSignOn.Repositories;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;

namespace MapleWebsite.SingleSignOn.Services;

public static class SingleSignOnService
{
    public static (string loginUrl, string samlRequest) GetLoginRequest(Guid companyId)
    {
        var settings = SingleSignOnSettingsRepository.GetSsoSettings(companyId);

        return (loginUrl: settings.LoginUrl, samlRequest: GetAuthRequest(companyId, settings));
    }

    public static (bool isSuccess, string userEmail) ValidateSamlResponse(string samlResponse)
    {
        var isSuccess = false;
        var userEmail = "";

        // the data sent us may be already decoded, which results in double decoding
        if (samlResponse.Contains('%'))
        {
            samlResponse = HttpUtility.UrlDecode(samlResponse);
        }

        // SAML response is always Base64, we need to decode it
        var decodedResponse = Base64Decode(samlResponse);

        var samlDocument = new XmlDocument { PreserveWhitespace = true };
        samlDocument.LoadXml(decodedResponse);

        var xmlManager = new XmlNamespaceManager(samlDocument.NameTable);
        xmlManager.AddNamespace("samlp", @"urn:oasis:names:tc:SAML:2.0:protocol");
        xmlManager.AddNamespace("asrt", @"urn:oasis:names:tc:SAML:2.0:assertion");
        xmlManager.AddNamespace("dsig", @"http://www.w3.org/2000/09/xmldsig#");

        var responseNode = samlDocument.SelectSingleNode("/samlp:Response", xmlManager);
        var assertionNode = responseNode.SelectSingleNode("asrt:Assertion", xmlManager);
        var signNode = assertionNode.SelectSingleNode("dsig:Signature", xmlManager);

        var companyId = Guid.NewGuid(); // Use 'InResponseTo' attribute to get ID from SAML request
        var settings = SingleSignOnSettingsRepository.GetSsoSettings(companyId);

        var isSigned = IsSignatureValid(samlDocument.DocumentElement, signNode, settings.Certificate);
        if (!isSigned)
        {
            return (false, "SAML response message signature is not valid");
        }

        var statusNode = responseNode.SelectSingleNode("samlp:Status/samlp:StatusCode/@Value", xmlManager);
        if (statusNode != null)
        {
            isSuccess = statusNode.Value?.Contains("success", StringComparison.InvariantCultureIgnoreCase) ?? false;
        }

        if (!isSuccess)
        {
            // Failed to pass login on Identity Provider side
            return (false, "Failed to login on Identity Provider side");
        }

        var issuerNode = assertionNode.SelectSingleNode("asrt:Issuer", xmlManager);
        if (issuerNode == null || settings.Identifier != issuerNode.InnerText)
        {
            return (false, "Invalid assertion issuer");
        }

        var conditionsNode = assertionNode.SelectSingleNode("asrt:Conditions", xmlManager);
        if (conditionsNode != null)
        {
            var now = DateTime.Now;

            var notBefore = DateTime.Parse(conditionsNode.Attributes["NotBefore"].Value);
            var notOnOrAfter = DateTime.Parse(conditionsNode.Attributes["NotOnOrAfter"].Value);

            isSuccess = now >= notBefore && now < notOnOrAfter;
        }

        var emailNode = assertionNode.SelectSingleNode("asrt:AttributeStatement", xmlManager)?
                                    .ChildNodes.Cast<XmlNode>().FirstOrDefault(c => c.Name.EndsWith("Attribute")
                                                                    && c.Attributes["Name"].Value.EndsWith("emailaddress"))?
                                    .ChildNodes[0]; // SAML Response always has only one "emailAddress" attribute
        if (emailNode != null)
        {
            userEmail = emailNode.InnerText;
        }

        return (isSuccess, userEmail);
    }

    public static (string logoutUrl, string samlRequest) GetLogoutUrl(Guid companyId)
    {
        var settings = SingleSignOnSettingsRepository.GetSsoSettings(companyId);

        var requestId = Guid.NewGuid();
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var notOnOrAfter = DateTime.UtcNow.AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ssZ");

        var nameId = "bFc/KZLg0Q1siYvgU3Z85Sk1WtKH6U/s2SmT5yWaEb8="; // from SAML Response Assertion/Subject/NameID

        var samlRequest = @$"<samlp:LogoutRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""  
   xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" 
   ID=""id_{requestId}"" 
   Version=""2.0"" 
   IssueInstant=""{timestamp}"" 
   Destination=""{settings.LogoutUrl}"" 
   NotOnOrAfter=""{notOnOrAfter}"" 
   Reason=""urn:oasis:names:tc:SAML:2.0:logout:user""> 
  <saml:Issuer>{settings.Identifier}</saml:Issuer> 
  <saml:NameID>{nameId}</saml:NameID> 
</samlp:LogoutRequest>";

        var base64Encoded = Base64Encode(samlRequest);

        return (logoutUrl: settings.LogoutUrl, samlRequest: base64Encoded);
    }

    private static bool IsSignatureValid(XmlElement documentElement, XmlNode signNode, string certificate)
    {
        var signedXml = new SignedXml(documentElement);
        signedXml.LoadXml(signNode as XmlElement);

        var x509Cert = new X509Certificate2(Encoding.UTF8.GetBytes(certificate));

        bool isSigned = signedXml.CheckSignature(x509Cert, true);

        return isSigned;
    }

    private static string GetAuthRequest(Guid companyId, SingleSignOnSamlSettings settings)
    {
        var requestId = $"{companyId}_{Guid.NewGuid()}";
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

        var authRequest = @$"<samlp:AuthnRequest
xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""
xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion""
ID=""id_{requestId}""
Version=""2.0""
IssueInstant=""{timestamp}""
AssertionConsumerServiceIndex=""0"">
<saml:Issuer>{settings.AppId}</saml:Issuer>
<samlp:NameIDPolicy
AllowCreate=""true""
Format=""urn:oasis:names:tc:SAML:2.0:nameid-format:transient""/>
</samlp:AuthnRequest>";

        var base64Encoded = Base64Encode(authRequest);
        return base64Encoded;
    }

    public static string Base64Encode(string plainText)
    {
        var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
        return Convert.ToBase64String(plainTextBytes);
    }

    public static string Base64Decode(string encodedText)
    {
        var plainBytes = Convert.FromBase64String(encodedText);
        return Encoding.UTF8.GetString(plainBytes);
    }
}
