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
    //private readonly ILogger<AccountController> _logger;


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
            UserName = model.Email,
            Email = model.Email,
            EmailConfirmed = true
        };
        var result = await _userManager.CreateAsync(user, model.Password);
        if (result.Succeeded)
        {
            //await _signInManager.SignInAsync(user, isPersistent: false);
            //RedirectToAction("Index", "Home");
            return Ok(new { message = "User registered successfully" });
        }
        return BadRequest(result.Errors);
    }

    //[HttpPost(Name="Login")]
    [HttpPost("api/Account/Login")]
    public async Task<IActionResult> Login(LoginDto model, string rturnUrl = null)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user != null)
        {
            var checkPassWord = await _userManager.CheckPasswordAsync(user, model.Password);
            if (!checkPassWord)
            {
                return BadRequest(new { message = "Invalid password" });
            }
            // Check if email is confirmed (if required)
            if (_userManager.Options.SignIn.RequireConfirmedEmail && !await _userManager.IsEmailConfirmedAsync(user))
            {
                return BadRequest(new { message = "Email not confirmed" });
            }
            if (await _userManager.IsLockedOutAsync(user))
            {
                return BadRequest(new { message = "Account is locked out" });
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, lockoutOnFailure: true);
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

                // Create a ClaimsIdentity
                var identity = new ClaimsIdentity(claims, "local");

                // Create a ClaimsPrincipal from the ClaimsIdentity
                var principal = new ClaimsPrincipal(identity);

                // Create a token request
                var tokenRequest = new TokenCreationRequest
                {
                    Subject = principal,
                    ValidatedResources = new ResourceValidationResult(),
                    ValidatedRequest = new ValidatedRequest()
                };

                // Generate the Token
                var token = await _tokenService.CreateAccessTokenAsync(tokenRequest);                

                // Create a security token
                //var tokenResult = await _tokenService.CreateSecurityTokenAsync(tokenRequest);
                var securityToken = new Token(IdentityServerConstants.TokenTypes.AccessToken)
                {
                    CreationTime = token.CreationTime,
                    Issuer = token.Issuer,
                    Lifetime = token.Lifetime,
                    Claims = token.Claims,
                    ClientId = token.ClientId,
                    AccessTokenType = token.AccessTokenType,
                    Description = token.Description,
                    Version = token.Version,
                };

                var tokenValue = await _tokenService.CreateSecurityTokenAsync(securityToken);

                return Ok(new
                {
                    access_token = tokenValue,
                    //access_token = tokenRequest.AccessTokenToHash,
                    toke_type = "Bearer",
                    //toke_type = tokenResult.TokenType,
                    expires_in = token.Lifetime
                    //expires_in = token.ExpiresIn
                });
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
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Display(Name = "Remember me?")]
    public bool RememberMe { get; set; }
}
