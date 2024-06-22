using Duende.IdentityServer.Models;

namespace IdentityServer.Infrastructure;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
    new IdentityResource[]
    {
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
    };

    public static IEnumerable<ApiScope> ApiScopes =>
    new ApiScope[]
    {
        new ApiScope("api1", "My API")
        //new ApiScope("api2", "My API")
    };

    public static IEnumerable<Client> Clients =>
    new Client[]
    {
        new Client
        {
            ClientId = "client",
            AllowedGrantTypes= GrantTypes.ClientCredentials,
            ClientSecrets =
            {
                new Secret("secret".Sha256())
            },
            AllowedScopes = {"api","api2" },
            AllowOfflineAccess = true,
            RefreshTokenUsage = TokenUsage.ReUse,
            RefreshTokenExpiration = TokenExpiration.Sliding,
            SlidingRefreshTokenLifetime = 86400 // 1 day
        },
        new Client
        {
            ClientId = "interactive",
            ClientSecrets = {new Secret("secret".Sha256())},
            AllowedGrantTypes = GrantTypes.Code,
            RedirectUris = {"https://localhost:5002/signin-oidc" },
            PostLogoutRedirectUris = {"https://localhost:5002/signout-callback-oidc"},
            AllowedScopes = {"openid", "profile", "api1", "api2"},
            RequirePkce = true,
            AllowOfflineAccess = true,
        }
    };
}
