using Duende.IdentityServer.Test;
using IdentityServer.Domain;
using IdentityServer.Infrastructure;
using IdentityServer.Infrastructure.DbContext;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

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
    //option.Events.RaiseErrorEvents = true;
    //option.Events.RaiseInformationEvents = true;
    //option.Events.RaiseFailureEvents = true;
    //option.Events.RaiseSuccessEvents = true;    
    //option.EmitStaticAudienceClaim = true;


    //option.AccessTokenJwtType = "at+jwt";
    //option.IssuerUri = "";
    //option.LogoutTokenJwtType = "logout+jwt";
    //option.Discovery.CustomEntries.Add("", "");
    //option.Cors.CorsPolicyName = "ICorsPolicyService";
})
    .AddInMemoryApiScopes(Config.ApiScopes)
    .AddInMemoryClients(Config.Clients)
    .AddInMemoryIdentityResources(Config.IdentityResources)
    .AddAspNetIdentity<ApplicationUser>()
    .AddDeveloperSigningCredential();

builder.Services.AddAuthentication()
    .AddJwtBearer("Bearer", options =>
    {
        options.Authority = "https://localhost:5001";
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false
        };
    });


// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

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
app.UseIdentityServer();
app.UseAuthorization();

app.MapControllers();
app.Run();
