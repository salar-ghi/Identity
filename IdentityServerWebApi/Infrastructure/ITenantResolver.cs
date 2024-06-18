namespace IdentityServerWebApi.Infrastructure;

public interface ITenantResolver
{
    Task<string> GetTenantIdAsync();
}
