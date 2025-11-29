
using Microsoft.AspNetCore.Identity;
using System.Data;

namespace WT.Domain.Entity
{
    public class WTUser : IdentityUser
    {
        public List<WTRole>? Roles { get; set; }
    }
}
