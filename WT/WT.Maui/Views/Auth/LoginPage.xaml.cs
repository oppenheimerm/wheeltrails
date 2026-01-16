using WT.Maui.ViewModels;

namespace WT.Maui.Views.Auth;

public partial class LoginPage : ContentPage
{
	public LoginPage(LoginViewModel vm)
	{
		InitializeComponent();
		BindingContext = vm;
    }
}