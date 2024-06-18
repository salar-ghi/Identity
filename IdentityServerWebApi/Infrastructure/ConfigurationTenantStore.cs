using IdentityServerWebApi.Configuration;

namespace IdentityServerWebApi.Infrastructure;

public class ConfigurationTenantStore : ITenantStore
{
    private readonly IConfiguration _configuration;

    public ConfigurationTenantStore(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public Task<TenantConfiguration> FindAsync(string tenantId)
    {
        var tenantConfig = new TenantConfiguration
        {
            Id = tenantId,
            ConnectionString = _configuration.GetConnectionString($"Tenant_{tenantId}")
        };

        return Task.FromResult(tenantConfig);
    }

    public Task SaveAsync(TenantConfiguration tenantConfiguration)
    {
        // Implement logic to save the tenant configuration
        return Task.CompletedTask;
    }
}
