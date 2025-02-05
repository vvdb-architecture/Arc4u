using Arc4u.OAuth2;
using Arc4u.OAuth2.Extensions;
using Arc4u.OAuth2.Middleware;
using Arc4u.OAuth2.Options;
using Arc4u.OAuth2.Token;
using AutoFixture;
using AutoFixture.AutoMoq;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Arc4u.UnitTest.Security;

[Trait("Category", "CI")]
public class BasicAuthenticationTests
{
    public BasicAuthenticationTests()
    {
        _fixture = new Fixture();
        _fixture.Customize(new AutoMoqCustomization());
    }

    private readonly Fixture _fixture;

    [Fact]
    public void Default_Authority_Should()
    {
        var defaultAuthority = BuildAuthority();

        var config = new ConfigurationBuilder()
                        .AddInMemoryCollection(
                               new Dictionary<string, string?>
                               {
                                   ["Authentication:DefaultAuthority:Url"] = defaultAuthority.Url.ToString(),
                                   ["Authentication:DefaultAuthority:TokenEndpoint"] = defaultAuthority.TokenEndpoint!.ToString(),

                               }).Build();

        IConfiguration configuration = new ConfigurationRoot(new List<IConfigurationProvider>(config.Providers));

        IServiceCollection services = new ServiceCollection();

        services.AddDefaultAuthority(configuration);

        var app = services.BuildServiceProvider();

        var sut = app.GetRequiredService<IOptionsMonitor<AuthorityOptions>>().Get("Default");

        sut.Url.Should().Be(defaultAuthority.Url);
        sut.TokenEndpoint.Should().Be(defaultAuthority.TokenEndpoint);
    }

    [Fact]
    public void Basic_With_Default_Authority_Should()
    {
        var basicSettings = _fixture.Create<BasicSettingsOptions>();

        var configDic = new Dictionary<string, string?>
        {
            ["Authentication:Basic:Settings:ClientId"] = basicSettings.ClientId,
        };
        foreach (var scope in basicSettings.Scopes)
        {
            configDic.Add($"Authentication:Basic:Settings:Scopes:{basicSettings.Scopes.IndexOf(scope)}", scope);
        }
        var config = new ConfigurationBuilder()
                        .AddInMemoryCollection(configDic).Build();

        IConfiguration configuration = new ConfigurationRoot(new List<IConfigurationProvider>(config.Providers));

        IServiceCollection services = new ServiceCollection();

        services.AddBasicAuthenticationSettings(configuration);

        var app = services.BuildServiceProvider();

        var sut = app.GetRequiredService<IOptionsMonitor<BasicAuthenticationSettingsOptions>>().CurrentValue;

        sut.BasicSettings.Values[TokenKeys.ClientIdKey].Should().Be(basicSettings.ClientId);
        sut.BasicSettings.Values[TokenKeys.Scope].Should().Be(string.Join(' ', basicSettings.Scopes));
        sut.BasicSettings.Values.ContainsKey(TokenKeys.AuthorityKey).Should().BeFalse();

        var sutAuthority = app.GetRequiredService<IOptionsMonitor<AuthorityOptions>>().Get("Basic");
    }

    [Fact]
    public void Basic_With_Dedicated_Authority_Should()
    {
        var authority = BuildAuthority();
        var basicSettings = _fixture.Create<BasicSettingsOptions>();

        var configDic = new Dictionary<string, string?>
        {
            ["Authentication:Basic:Settings:ClientId"] = basicSettings.ClientId,
            ["Authentication:Basic:Settings:Authority:url"] = authority.Url.ToString(),
            ["Authentication:Basic:Settings:Authority:TokenEndpoint"] = authority.TokenEndpoint!.ToString(),

        };
        foreach (var scope in basicSettings.Scopes)
        {
            configDic.Add($"Authentication:Basic:Settings:Scopes:{basicSettings.Scopes.IndexOf(scope)}", scope);
        }
        var config = new ConfigurationBuilder()
                        .AddInMemoryCollection(configDic).Build();

        IConfiguration configuration = new ConfigurationRoot(new List<IConfigurationProvider>(config.Providers));

        IServiceCollection services = new ServiceCollection();

        services.AddBasicAuthenticationSettings(configuration);

        var app = services.BuildServiceProvider();

        var sut = app.GetRequiredService<IOptionsMonitor<BasicAuthenticationSettingsOptions>>().CurrentValue;

        sut.BasicSettings.Values[TokenKeys.ClientIdKey].Should().Be(basicSettings.ClientId);
        sut.BasicSettings.Values[TokenKeys.Scope].Should().Be(string.Join(' ', basicSettings.Scopes));
        sut.BasicSettings.Values[TokenKeys.AuthorityKey].Should().Be("Basic");

        var sutAuthority = app.GetRequiredService<IOptionsMonitor<AuthorityOptions>>().Get("Basic");

        sutAuthority.Url.Should().Be(authority.Url);
        sutAuthority.TokenEndpoint.Should().Be(authority.TokenEndpoint);
    }

    private AuthorityOptions BuildAuthority() => _fixture.Build<AuthorityOptions>().With(p => p.TokenEndpoint, _fixture.Create<Uri>()).Create();
}
