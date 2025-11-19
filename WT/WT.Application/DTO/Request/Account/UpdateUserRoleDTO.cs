namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Used to update a user's role based on their email address.
    /// </summary>
    /// <param name="EmailAddress"></param>
    /// <param name="RoleCode"></param>
    public record UpdateUserRoleDTO(string EmailAddress, string RoleCode);
}
