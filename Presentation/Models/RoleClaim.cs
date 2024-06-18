using System.Security.Claims;

namespace Presentation.Models
{
    public class RoleClaim : Claim
    {
        public RoleClaim(string type, string value) :  base(type, value)
        {            
        }
    }
}
