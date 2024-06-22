using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Domain;

public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public DateTime DateOfBirth { get; set; }
    //public List<string> Roles { get; set; }
    //public List<string> Permissions { get; set; }
}
