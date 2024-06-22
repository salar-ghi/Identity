using Duende.IdentityServer.Test;
using IdentityServerWebApi.Domain;
using IdentityServerWebApi.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

namespace IdentityServerWebApi;

public class Startup
{

    public IConfiguration Configuration { get; }
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers(options => {});

        var connectionString = Configuration.GetConnectionString("IdentityServerCon");

        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(connectionString));

        services.AddIdentity<ApplicationUser, ApplicationRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        services.AddIdentityServer()
            .AddAspNetIdentity<ApplicationUser>()
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryClients(Config.Clients)
            .AddInMemoryIdentityResources(Config.IdentityResources)
            .AddDeveloperSigningCredential();

            //.AddConfigurationStore(options =>
            //{
            //    options.ConfigureDbContext = builder =>
            //        builder.UseSqlServer(connectionString);
            //})
            //.AddOperationalStore(options =>
            //{
            //    options.ConfigureDbContext = builder =>
            //        builder.UseSqlServer(connectionString);
            //})
            //.AddDeveloperSigningCredential();


        services.AddAuthentication()
            //.AddIdentityServerAuthentication(options =>
            //{
            //    options.Authority = IdentityServerConfig.Authority;
            //    options.RequireHttpsMetadata = false;
            //})
            .AddJwtBearer("Bearer", options =>
            {
                options.Authority = IdentityServerConfig.Authority;
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters =
                    new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = IdentityServerConfig.Authority,
                        ValidAudience = IdentityServerConfig.ClientId,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your_secret_key_here"))
                    };
            });

        //services.AddAuthorization(options =>
        //{
        //    options.AddPolicy("RequireRole", policy =>
        //    {
        //        policy.RequireClaim(ClaimTypes.Role);
        //    });
        //});

        //services.AddSingleton<ITenantResolver, TenantResolver>();

        //services.AddMultiTenancy()
        //    .WithTenantResolver<TenantResolver>()
        //    .WithStore<ConfigurationTenantStore>();
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen();
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {

        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseSwagger();
            app.UseSwaggerUI();
        }
        app.UseRouting();
        app.UseIdentityServer();
        //app.UseAuthentication();
        app.UseAuthorization();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });

        
        //app.UseIdentityServerBearerTokenAuthentication(new IdentityServerBearerTokenAuthenticationOptions
        //{
        //    Authority = "https://localhost:5000",
        //    RequiredScopes = new[] { "scope1" },
        //    ClientId = "client",
        //    ClientSecret = "secret"
        //});
    }
}
