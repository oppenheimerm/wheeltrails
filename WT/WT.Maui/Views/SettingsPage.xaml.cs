using System;
using Microsoft.Maui.Controls;
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

        // Handler wired from XAML: updates viewmodel and triggers the command.
        void ThemeSwitch_Toggled(object? sender, ToggledEventArgs e)
        {
            if (BindingContext is not SettingsViewModel vm) return;

            // Update ViewModel property (two-way binding may already do this).
            vm.IsDarkMode = e.Value;

            // Prefer invoking the RelayCommand to persist and apply theme.
            if (vm.ToggleThemeCommand.CanExecute(null))
            {
                vm.ToggleThemeCommand.Execute(null);
            }
        }
    }
}