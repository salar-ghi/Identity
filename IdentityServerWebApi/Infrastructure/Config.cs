using Duende.IdentityServer;
using Duende.IdentityServer.Models;

namespace IdentityServerWebApi.Infrastructure;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
    new IdentityResource[]
    {
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
        //new IdentityResource("roles", "User roles", new[] { "role" })
    };

    public static IEnumerable<ApiScope> ApiScopes =>
    new ApiScope[]
    {
        new ApiScope("api1", "My API"),
        new ApiScope("api2", "My API")
    };

    public static IEnumerable<Client> Clients =>
    new Client[]
    {
        // SPA client using code flow + pkce
        //new Client
        //{
        //    ClientId = "client",
        //    ClientSecrets = { new Secret("secret".Sha256()) },

        //    AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
        //    RequirePkce = true,
        //    RequireClientSecret = true,

        //    RedirectUris = { "https://localhost:5001/signin-oidc" },
        //    FrontChannelLogoutUri = "https://localhost:5001/signout-oidc",
        //    PostLogoutRedirectUris = { "https://localhost:5001/" },

        //    AllowOfflineAccess = true,
        //    AllowedScopes =
        //    {
        //        IdentityServerConstants.StandardScopes.OpenId,
        //        IdentityServerConstants.StandardScopes.Profile,
        //        "api1",
        //        "api2",
        //        "roles"
        //    }
        //},
        new Client
        {
            ClientId = "Client",
            AllowedGrantTypes= GrantTypes.ResourceOwnerPasswordAndClientCredentials,
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
