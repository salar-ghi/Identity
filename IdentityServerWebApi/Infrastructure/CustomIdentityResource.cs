using Duende.IdentityServer.Models;

namespace IdentityServerWebApi.Infrastructure;

public class CustomIdentityResource : IdentityResource
{
    public CustomIdentityResource(string name, string displayName, IEnumerable<string> claimTypes)
        : base(name, displayName, claimTypes)
    {
    }

    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        {
        new CustomIdentityResource("custom_profile", "Custom Profile", new[] { "custom_claim" })
        };
}
