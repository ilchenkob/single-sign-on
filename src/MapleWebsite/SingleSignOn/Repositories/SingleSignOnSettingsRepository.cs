using MapleWebsite.SingleSignOn.Models;

namespace MapleWebsite.SingleSignOn.Repositories;

public static class SingleSignOnSettingsRepository
{
    public static SingleSignOnSamlSettings GetSsoSettings(Guid companyId)
    {
        return new SingleSignOnSamlSettings();
    }
}
