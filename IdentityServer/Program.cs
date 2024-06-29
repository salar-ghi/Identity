using Duende.IdentityServer;
using IdentityServer.Domain;
using IdentityServer.Infrastructure;
using IdentityServer.Infrastructure.DbContext;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using Microsoft.IdentityModel.Logging;

using Duende.IdentityServer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

var connectionString = builder.Configuration.GetConnectionString("IdentityServerCon");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddIdentity<ApplicationUser, ApplicationRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddIdentityServer(option =>
{
    option.Events.RaiseErrorEvents = true;
    option.Events.RaiseInformationEvents = true;
    option.Events.RaiseFailureEvents = true;
    option.Events.RaiseSuccessEvents = true;

    //option.EmitStaticAudienceClaim = true;


    //option.AccessTokenJwtType = "at+jwt";
    //option.IssuerUri = "";
    //option.LogoutTokenJwtType = "logout+jwt";
    //option.Discovery.CustomEntries.Add("", "");
    //option.Cors.CorsPolicyName = "ICorsPolicyService";
})
    //.AddApiAuthorization<ApplicationUser, ApplicationDbContext>()
    .AddInMemoryIdentityResources(Config.IdentityResources)
    .AddInMemoryApiScopes(Config.ApiScopes)
    .AddInMemoryClients(Config.Clients)
    .AddAspNetIdentity<ApplicationUser>()
    .AddConfigurationStore(options =>
    {
        //options.ConfigureDbContext = b => b.UseSqlServer(connectionString);

        options.ConfigureDbContext = b => b.UseSqlServer(connectionString,
            sql => sql.MigrationsAssembly(typeof(Program).Assembly.GetName().Name));
    })
    .AddOperationalStore(options =>
    {
        //options.ConfigureDbContext = b => b.UseSqlServer(connectionString);
        options.ConfigureDbContext = b => b.UseSqlServer(connectionString,
            sql => sql.MigrationsAssembly(typeof(Program).Assembly.GetName().Name));
    })    
    .AddDeveloperSigningCredential(); // Not recommended for production

//builder.Services.AddAuthentication()
//    .AddJwtBearer("Bearer", options =>
//    {
//        options.Authority = "https://localhost:5001";
//        options.TokenValidationParameters = new TokenValidationParameters
//        {
//            ValidateAudience = false
//        };
//    });


// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
builder.Logging.AddConsole();
builder.Logging.AddDebug();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseRouting();
IdentityModelEventSource.ShowPII = true;

app.UseIdentityServer();
app.UseAuthorization();

app.MapControllers();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        context.Database.Migrate();

        var configContext = services.GetRequiredService<ConfigurationDbContext>();
        configContext.Database.Migrate();

        var operationalContext = services.GetRequiredService<PersistedGrantDbContext>();
        operationalContext.Database.Migrate();

        SeedData.EnsureSeedData(services);
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while migrating or initializing");
        throw;
    }
}


app.Run();
