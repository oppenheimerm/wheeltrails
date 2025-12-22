
using WT.Application.DTO.Response;

namespace WT.Application.Extensions
{
    public static class Constants
    {
        public static class Role
        {
            public const string ADMIN_EDITOR = "ADMIN_EDITOR";
            public const string ADMIN_DEVELOPER = "ADMIN_DEVELOPER";
            public const string USER = "USER";
            public const string USER_EDITOR = "USER_EDITOR";

        }

        public static class FirebaseUploadConstants
        {
            /// <summary>
            /// Maximum allowed size for profile picture uploads in bytes.
            /// </summary>
            public const long MaxProfilePictureSize = 3 * 1024 * 1024; // 3MB
        }

    }
}