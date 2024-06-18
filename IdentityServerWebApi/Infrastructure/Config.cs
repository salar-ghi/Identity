using Duende.IdentityServer;
using Duende.IdentityServer.Models;

namespace IdentityServerWebApi.Infrastructure;

public class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
    new IdentityResource[]
    {
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
        new IdentityResource("roles", "User roles", new[] { "role" })
    };

    public static IEnumerable<ApiScope> ApiScopes =>
    new ApiScope[]
    {
        new ApiScope("api1", "My API")
    };

    public static IEnumerable<Client> Clients =>
    new Client[]
    {
        // SPA client using code flow + pkce
        new Client
        {
            ClientId = "client",
            ClientSecrets = { new Secret("secret".Sha256()) },

            AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
            RequirePkce = true,
            RequireClientSecret = true,

            RedirectUris = { "https://localhost:5001/signin-oidc" },
            FrontChannelLogoutUri = "https://localhost:5001/signout-oidc",
            PostLogoutRedirectUris = { "https://localhost:5001/" },

            AllowOfflineAccess = true,
            AllowedScopes =
            {
                IdentityServerConstants.StandardScopes.OpenId,
                IdentityServerConstants.StandardScopes.Profile,
                "api1",
                "roles"
            }
        }
    };
}
