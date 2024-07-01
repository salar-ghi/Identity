using Azure.Core;
using Duende.AccessTokenManagement.OpenIdConnect;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Validation;
using IdentityModel;
using IdentityServer.Domain;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace IdentityServer.Controllers;

[ApiController]
[Route("[controller]")]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IClientStore _clientStore;    
    private readonly ITokenService _tokenService;
    private readonly IConfiguration _config;


    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IIdentityServerInteractionService interaction,
        IClientStore clientStore,
        ITokenService tokenService,
        IConfiguration config)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _interaction = interaction;
        _clientStore = clientStore;
        _tokenService = tokenService;
        _config = config;
    }


    [HttpGet]
    public IActionResult Result()
    {
        return Ok();
    }

    //[HttpPost(Name="Register")]
    [HttpPost("api/Account/Register")]
    public async Task<IActionResult> Register(RegisterDto model)
    {
        var user = new ApplicationUser
        {
            FirstName = model.FirstName,
            LastName = model.LastName,
            UserName = model.FirstName,
            Email = model.Email,
            EmailConfirmed = true
        };
        var result = await _userManager.CreateAsync(user, model.Password);
        if (result.Succeeded)
        {
            await _signInManager.SignInAsync(user, isPersistent: false);
            return Ok(new { access_token = await GenerateAccessToken(user) });
        }
        return BadRequest(result.Errors);
    }

    [HttpPost("api/Account/Login1")]
    public async Task<IActionResult> Login1(LoginDto model, string rturnUrl = null)
    {
        var userValid = await _userManager.FindByEmailAsync(model.Email);
        if (userValid != null)
        {
            var isPasswordValid = await _userManager.CheckPasswordAsync(userValid, model.Password);
            if (await _userManager.IsLockedOutAsync(userValid))
            {
                return BadRequest(new { message = "Account is locked out" });
            }
            if (_userManager.Options.SignIn.RequireConfirmedEmail && !await _userManager.IsEmailConfirmedAsync(userValid))
            {
                return BadRequest(new { message = "Email not confirmed" });
            }

            var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, false, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByNameAsync(model.Username);
                var accToken = await GenerateAccessToken(user);
                return Ok(new { access_token = accToken });
            }
            else if (result.IsLockedOut)
            {
                return BadRequest(new { message = "Account locked out" });
            }
            else if (result.IsNotAllowed)
            {
                return BadRequest(new { message = "Login not allowed" });
            }
            else if (result.RequiresTwoFactor)
            {
                return BadRequest(new { message = "Requires two-factor authentication" });
            }
        }
        return Unauthorized(new { message = "Invalid login attemp" });
    }


    private async Task<string> GenerateAccessToken(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtClaimTypes.Subject, user.Id),
            new Claim(JwtClaimTypes.Name, user.UserName ?? ""),
            new Claim(JwtClaimTypes.Email, user.Email ?? ""),
            new Claim("role", "admin")
        };
        //var email = context.Subject.FindFirst(JwtClaimTypes.Email)?.Value ?? "default@example.com";


        var identity = new ClaimsIdentity(claims, "Bearer");
        var principal = new ClaimsPrincipal(identity);

        //var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));
        Console.WriteLine($"IsAuthenticated: {principal.Identity?.IsAuthenticated}");


        var tokenRequest = new TokenCreationRequest
        {
            Subject = principal,
            AccessTokenToHash = user.Id,
            AuthorizationCodeToHash = user.Id,
            Description = "",
            IncludeAllIdentityClaims = true,
            StateHash = user.Id,
            Nonce = user.Id,
            ValidatedResources = new ResourceValidationResult
            {
                Resources = new Resources
                {
                    IdentityResources = new[]
                    {
                        new IdentityResource("openid", new[] { JwtClaimTypes.Subject }),
                        new IdentityResource("profile", new[] { JwtClaimTypes.Name, JwtClaimTypes.Email })
                    },
                    ApiScopes = new[]
                    {
                        new ApiScope("api1")
                    }
                }
            },
            ValidatedRequest = new ValidatedRequest
            {
                Client = new Client
                {
                    ClientId = "spa",
                    AllowedGrantTypes = GrantTypes.Code,
                    RequireClientSecret = false,
                    RedirectUris = { "http://localhost:50005/callback" },
                    PostLogoutRedirectUris = { "http://localhost:5005" },
                    AllowedScopes = { "openid", "profile", "api1", "roles" }
                }
            }
        };
        CheckNullValues(tokenRequest);
        //var accessToken = await _tokenService.CreateAccessTokenAsync(tokenRequest);
        //var accessToken = await _accessToken.GetAccessTokenAsync(principal);
        var tokenResult = await _tokenService.CreateAccessTokenAsync(tokenRequest);
        var tknResult = tokenRequest.AccessTokenToHash;
        //var accessToken = await _tokenService.CreateTokenAsync(tokenRequest);
        Console.WriteLine($"accessToken : => {tokenResult}");
        return tknResult;
    }

    //[HttpPost(Name="Login")]
    [HttpPost("api/Account/Login")]
    public async Task<IActionResult> Login(LoginDto model, string rturnUrl = null)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user != null)
        {
            //var checkPassWord = await _userManager.CheckPasswordAsync(user, model.Password);
            //if (!checkPassWord)
            //{
            //    return BadRequest(new { message = "Invalid password" });
            //}
            //if (_userManager.Options.SignIn.RequireConfirmedEmail && !await _userManager.IsEmailConfirmedAsync(user))
            //{
            //    return BadRequest(new { message = "Email not confirmed" });
            //}
            //if (await _userManager.IsLockedOutAsync(user))
            //{
            //    return BadRequest(new { message = "Account is locked out" });
            //}

            var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, false, lockoutOnFailure: false);
            //var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if (result.Succeeded)
            {


                //var user = await _userManager.FindByEmailAsync(model.Email);
                //if (user == null)
                //{
                //    return BadRequest(new { message = "User not found" });
                //}

                //// Here you would typically geneate and return a token

                // Create claims for the user
                var claims = new List<Claim>
                {
                    new Claim("sub", user.Id),
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Email, user.Email)
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var jwtToken = new JwtSecurityToken(
                    issuer: _config["Jwt:Issuer"],
                    audience: _config["Jwt:Audience"],
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: creds
                    );
                //return Ok(new
                //{
                //    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                //    expiration = jwtToken.ValidTo
                //});

                var identity = new ClaimsIdentity(claims, "local");
                var principal = new ClaimsPrincipal(identity);

                //var principal = await _signInManager.CreateUserPrincipalAsync(user);
                //if (VerifyUserClaims(principal))
                //{
                    // Create a token request
                    var tokenRequest = new TokenCreationRequest
                    {
                        Subject = principal,
                        ValidatedResources = new ResourceValidationResult(),
                        ValidatedRequest = new ValidatedRequest()
                    };

                    // Generate the Token 
                    //var accessToken = await _accessToken.GetAccessTokenAsync(principal);
                    var token = await _tokenService.CreateAccessTokenAsync(tokenRequest);
                    if (token == null)
                    {
                        return StatusCode(500, "Internal server error");
                    }
                    return Ok(new
                    {
                        access_token = token.ToString(),
                        token_type = "Bearer",
                        expires_in = token.Lifetime
                    });
                //}

                // Create a security token
                //var tokenResult = await _tokenService.CreateSecurityTokenAsync(tokenRequest);
                //var securityToken = new Token(IdentityServerConstants.TokenTypes.AccessToken)
                //{
                //    CreationTime = token.CreationTime,
                //    Issuer = token.Issuer,
                //    Lifetime = token.Lifetime,
                //    Claims = token.Claims,
                //    ClientId = token.ClientId,
                //    AccessTokenType = token.AccessTokenType,
                //    Description = token.Description,
                //    Version = token.Version,
                //};

                //var tokenValue = await _tokenService.CreateSecurityTokenAsync(securityToken);

                //return Ok(new
                //{
                //    access_token = tokenValue,
                //    //access_token = tokenRequest.AccessTokenToHash,
                //    toke_type = "Bearer",
                //    //toke_type = tokenResult.TokenType,
                //    expires_in = token.Lifetime
                //    //expires_in = token.ExpiresIn
                //});
            }
            if (result.IsLockedOut)
            {
                return BadRequest(new { message = "Account locked out" });
            }
            if (result.IsNotAllowed)
            {
                return BadRequest(new { message = "Login not allowed" });
            }
            if (result.RequiresTwoFactor)
            {
                return BadRequest(new { message = "Requires two-factor authentication" });
            }
        }
        return Unauthorized(new { message = "Invalid login attemp" });
    }

    private bool VerifyUserClaims(ClaimsPrincipal principal)
    {
        // Verify the user's claims here
        // For example, check if the user has a specific role or claim:
        if (principal.HasClaim(c => c.Type == "role" && c.Value == "admin"))
        {
            return true;
        }

        return false;
    }
    private IActionResult RedirectToLocal(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        else
        {
            return RedirectToAction(nameof(WeatherForecastController.Get), "WeatherForecast");
        }
    }


    private void CheckNullValues(TokenCreationRequest tokenRequest)
    {
        if (tokenRequest == null)
        {
            Console.WriteLine("tokenRequest is null");
            return;
        }

        if (tokenRequest.Subject == null)
            Console.WriteLine("tokenRequest.Subject is null");

        if (tokenRequest.ValidatedResources == null)
            Console.WriteLine("tokenRequest.ValidatedResources is null");
        else
        {
            if (tokenRequest.ValidatedResources.Resources == null)
                Console.WriteLine("tokenRequest.ValidatedResources.Resources is null");
            else
            {
                if (tokenRequest.ValidatedResources.Resources.IdentityResources == null)
                    Console.WriteLine("tokenRequest.ValidatedResources.Resources.IdentityResources is null");
                if (tokenRequest.ValidatedResources.Resources.ApiScopes == null)
                    Console.WriteLine("tokenRequest.ValidatedResources.Resources.ApiScopes is null");
            }
        }

        if (tokenRequest.ValidatedRequest == null)
            Console.WriteLine("tokenRequest.ValidatedRequest is null");
        else
        {
            if (tokenRequest.ValidatedRequest.Client == null)
                Console.WriteLine("tokenRequest.ValidatedRequest.Client is null");
            else
            {
                if (string.IsNullOrEmpty(tokenRequest.ValidatedRequest.Client.ClientId))
                    Console.WriteLine("tokenRequest.ValidatedRequest.Client.ClientId is null or empty");
                if (tokenRequest.ValidatedRequest.Client.AllowedGrantTypes == null)
                    Console.WriteLine("tokenRequest.ValidatedRequest.Client.AllowedGrantTypes is null");
                if (tokenRequest.ValidatedRequest.Client.RedirectUris == null)
                    Console.WriteLine("tokenRequest.ValidatedRequest.Client.RedirectUris is null");
                if (tokenRequest.ValidatedRequest.Client.PostLogoutRedirectUris == null)
                    Console.WriteLine("tokenRequest.ValidatedRequest.Client.PostLogoutRedirectUris is null");
                if (tokenRequest.ValidatedRequest.Client.AllowedScopes == null)
                    Console.WriteLine("tokenRequest.ValidatedRequest.Client.AllowedScopes is null");
            }
        }
    }
}

public class RegisterDto
{

    [Required]
    public string FirstName { get; set; }

    [Required]
    public string LastName { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [DataType(DataType.Password)]
    [Display(Name = "Confirm password")]
    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; }
}

public class LoginDto
{
    public string Username { get; set; }
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Display(Name = "Remember me?")]
    public bool RememberMe { get; set; }
}
