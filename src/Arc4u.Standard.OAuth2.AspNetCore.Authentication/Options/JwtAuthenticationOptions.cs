using System.Security.Cryptography.X509Certificates;
using Arc4u.OAuth2.Configuration;
using Arc4u.OAuth2.Events;

namespace Arc4u.OAuth2.Options;
public class JwtAuthenticationOptions
{
    public AuthorityOptions DefaultAuthority { get; set; } = new AuthorityOptions();
    public Action<OAuth2SettingsOption> OAuth2SettingsOptions { get; set; } = default!;
    public Action<ClaimsIdentifierOption> ClaimsIdentifierOptions { get; set; } = default!;

    public string OAuth2SettingsKey { get; set; } = Constants.OAuth2OptionsName;

    public bool ValidateAuthority { get; set; } = true;

    public Type JwtBearerEventsType { get; set; } = typeof(StandardBearerEvents);

    public X509Certificate2? CertSecurityKey { get; set; } = default!;
}
