using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Presentation.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Presentation.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;


    public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        var user = new ApplicationUser
        { 
            UserName = model.Email,
            Email = model.Email,
            FirstName = model.FirstName,
            LastName = model.LastName,
        };

        var result = await _userManager.CreateAsync(user, model.Password);
        if (result.Succeeded)
        {
            //await _userManager.AddClaimAsync(user, new RoleClaim(ClaimTypes.Role, "admin"));
            await _userManager.AddClaimAsync(user, new RoleClaim(ClaimTypes.Role, "user"));
            return Ok();
        }
        return BadRequest(result.Errors);
    }


    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);
        if (result.Succeeded)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            var token = await GenerateToken(user);
            return Ok(new { token });
        }
        return Unauthorized();
    }


    private async Task<string> GenerateToken(ApplicationUser user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SecretKey")); // ??? SEcret Key
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Id),
            new Claim(ClaimTypes.Email, user.Email)
        };
        
        var userClaims = await _userManager.GetClaimsAsync(user);
        claims.AddRange(userClaims);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(new[] {new Claim(ClaimTypes.Name, user.Id)}),
            Expires = DateTime.UtcNow.AddMinutes(180),
            SigningCredentials = creds,
        };
        //var roles = claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);
        //tokenDescriptor.Subject.AddClaim(roles.Select(r => new Claim(ClaimTypes.Role, r)));
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}


public class RegisterModel
{
    public string Email { get; set; }
    public string Password { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
}

public class LoginModel
{
    public string Email { get; set; }
    public string Password { get; set; }
}