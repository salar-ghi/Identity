using Duende.IdentityServer.Models;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer.Infrastructure;

public class Config
{
    private static IdentityResources.OpenId _openid;

    public Config()
    {
        _openid = new IdentityResources.OpenId();
        //_openid.UserClaims.Add("acr");
    }


    public static IEnumerable<IdentityResource> IdentityResources =>
    new IdentityResource[]
    {
        //_openid
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
        new IdentityResource
        {
            Name = "roles",
            UserClaims = new List<string>{ "role"}
        }
    };

    public static IEnumerable<ApiScope> ApiScopes =>
    //new ApiScope[]
    new List<ApiScope>
    {
        new ApiScope(name:"weatherapi.read", displayName:"Read Your Data."),
        new ApiScope(name:"weatherapi.write", displayName:"write Your Data."),
        new ApiScope("api1", "My API"),
        new ApiScope("scope1", new[]{ "acr" }),
        new ApiScope("scope2", new[]{ "acr" }),
    };
    public static IEnumerable<ApiResource> ApiResources => new[]
    {
        new ApiResource("weatherapi")
        {
            Scopes =new List<string> { "weatherapi.read", "weatherapi.write" },
            ApiSecrets = new List<Secret> {new Secret("ScopeSecret".Sha256())},
            UserClaims = new List<string> {"role"}
            //AllowedAccessTokenSigningAlgorithms = { SecurityAlgorithms.RsaSsaPssSha256 }
        }
    };

    public static IEnumerable<Client> Clients =>
    new Client[]
    {
        //new Client
        //{
        //    ClientId = "web_viewer",
        //    AllowedScopes = {"openid", "profile", "read"}
        //},
        //new Client
        //{
        //    ClientId = "step-up",
        //    ClientName = "Step Up Demo",
        //    ClientSecrets = { new Secret("secret".Sha256()) },
        //    AllowedGrantTypes = GrantTypes.Code,
        //    RedirectUris = { "https://localhost:6001/signin-oidc" },
        //    FrontChannelLogoutUri = "https://localhost:6001/signout-oidc",
        //    PostLogoutRedirectUris = { "https://localhost:6001/signout-callback-oidc" },
        //    AllowedScopes = { "openid", "profile", "scope1" }
        //},
        new Client
        {
            ClientId = "client",
            AllowedGrantTypes= GrantTypes.ClientCredentials,
            ClientSecrets =
            {
                new Secret("secret".Sha256())
            },
            //AllowedScopes = { "scope1" },
            AllowedScopes = { "api1" },
            //AllowOfflineAccess = true,
            //RefreshTokenUsage = TokenUsage.ReUse,
            //RefreshTokenExpiration = TokenExpiration.Sliding,
            //SlidingRefreshTokenLifetime = 86400 // 1 day
        },
        new Client
        {
            ClientId = "webApi",
            ClientName = "WebApi client",
            AllowedGrantTypes = GrantTypes.Code,
            RequireClientSecret = false,
            RequirePkce = true,
            RedirectUris = {"http://localhost:5005/callback"},
            PostLogoutRedirectUris = {"http://localhost:5005/"},
            AllowedCorsOrigins = {"http://localhost:5005"},
            AllowedScopes = {"openid", "profile", "api1", "roles"}
        },
        //new Client
        //{
        //    ClientId = "interactive",
        //    ClientSecrets = {new Secret("secret".Sha256())},
        //    AllowedGrantTypes = GrantTypes.Code,
        //    RedirectUris = {"https://localhost:5002/signin-oidc" },
        //    PostLogoutRedirectUris = {"https://localhost:5002/signout-callback-oidc"},
        //    AllowedScopes = {"openid", "profile", "scope2"},
        //    RequirePkce = true,
        //    AllowOfflineAccess = true,
        //}
    };
}
