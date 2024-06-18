using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Presentation.Attributes;
using System.Security.Claims;

namespace Presentation.Filters;

public class AuthorizeFilter : IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var user = context.HttpContext.User;
        if (!user.Identity.IsAuthenticated)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        var roles = context.ActionDescriptor.EndpointMetadata.OfType<AuthorizeAttribute>().SelectMany(a => a.Roles);
        if (roles.Any())
        {
            var userRoles = user.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);
            if (!roles.All(r => userRoles.Contains(r)))
            {
                context.Result = new UnauthorizedResult();
                return;
            }
        }
    }
}
