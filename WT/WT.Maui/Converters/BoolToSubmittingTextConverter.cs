using System;
using System.Globalization;
using Microsoft.Maui.Controls;

namespace WT.Maui.Converters
{
    public class BoolToSubmittingTextConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool b && b)
                return "Signing in...";

            return "Sign in";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }
}
