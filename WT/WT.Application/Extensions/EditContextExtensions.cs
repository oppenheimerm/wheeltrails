using Microsoft.AspNetCore.Components.Forms;

namespace WT.Application.Extensions
{
    public static class EditContextExtensions
    {
        /// <summary>
        /// Adds a validation error to the EditContext's ValidationMessageStore for the model as a general error.
        /// </summary>
        /// <param name="editContext">The EditContext instance.</param>
        /// <param name="errorMessage">The error message to display.</param>
        public static void AddValidationErrors(this EditContext editContext, string errorMessage)
        {
            if (editContext == null || string.IsNullOrWhiteSpace(errorMessage))
                return;

            var validationMessageStore = new ValidationMessageStore(editContext);
            // Fix: Use FieldIdentifier for the model itself (empty field name for general error)
            var modelField = new FieldIdentifier(editContext.Model, string.Empty);
            validationMessageStore.Add(modelField, errorMessage);
            // Notify the UI that validation state has changed
            editContext.NotifyValidationStateChanged();
        }
    }
}
