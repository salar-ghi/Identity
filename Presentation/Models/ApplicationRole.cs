using Microsoft.AspNetCore.Identity;

namespace Presentation.Models;

public class ApplicationRole : IdentityRole
{
    public string Description { get; set; }
}
