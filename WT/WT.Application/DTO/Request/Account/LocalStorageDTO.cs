using System;
using System.Collections.Generic;
using System.Text;

namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// When we receive a token from the API on authentication, we need to store the token to 
    /// local storage on the client side. This DTO represents the structure of the data
    /// </summary>

    public class LocalStorageDTO
    {
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }
    }
}
