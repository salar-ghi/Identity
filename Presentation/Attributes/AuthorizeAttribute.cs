namespace Presentation.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class AuthorizeAttribute : Attribute
{
    public string[] Roles { get; set; }
}
