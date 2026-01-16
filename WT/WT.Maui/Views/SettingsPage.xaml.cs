using WT.Maui.ViewModels;

namespace WT.Maui.Views
{
    public partial class SettingsPage : ContentPage
    {
        public SettingsPage(SettingsViewModel vm)
        {
            InitializeComponent();
            BindingContext = vm;
        }
    }
}