namespace IdentityServerWebApi.Infrastructure;

public class TenantResolver : ITenantResolver
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IConfiguration _configuration;
    public TenantResolver(IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
    {
        _httpContextAccessor = httpContextAccessor;
        _configuration = configuration;
    }

    public async Task<string> GetTenantIdAsync()
    {
        var tenantId = _httpContextAccessor.HttpContext?.Request.Headers["X-TenantId"].FirstOrDefault();
        if (string.IsNullOrEmpty(tenantId))
        {
            // Fallback to a default tenant if the tenant ID is not provided
            tenantId = _configuration.GetValue<string>("DefaultTenantId");
        }

        return tenantId;
    }


}
