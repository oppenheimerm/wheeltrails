namespace WT.Application.DTO.Response
{
    /// <summary>
    /// Data transfer object for username validation results.
    /// Contains validation status, availability, and message.
    /// </summary>
    public class UsernameValidationResultDTO
    {
        /// <summary>
        /// Overall validation status (true if username passes all checks).
        /// </summary>
        public bool IsValid { get; set; }
        
        /// <summary>
        /// Availability status (true if username is not taken by another user).
        /// </summary>
        public bool IsAvailable { get; set; }
        
        /// <summary>
        /// Detailed message indicating the result of validation.
        /// </summary>
        public string Message { get; set; } = string.Empty;
    }
}
