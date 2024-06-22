using IdentityServerWebApi.Domain;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServerWebApi.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManger)
    {
        _userManager = userManager;
        _signInManager = signInManger;
    }

    //[HttpPost("register")]
    //public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
    //{

    //}

    

}
