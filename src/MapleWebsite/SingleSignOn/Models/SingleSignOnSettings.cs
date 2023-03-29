namespace MapleWebsite.SingleSignOn.Models;

// Azure Active Directory
public class SingleSignOnSamlSettings
{
    public string LoginUrl { get; set; } = "https://login..../saml2";

    public string AppId { get; set; } = "application-name"; // Identifier (Entity ID)

    public string Identifier { get; set; } = "https://sts.windows.../"; // Azure AD Identifier

    public string LogoutUrl { get; set; } = "https://login..../saml2";

    // Base64 certificate
    public string Certificate { get; set; } = @"MIIC8m43C....";
}
