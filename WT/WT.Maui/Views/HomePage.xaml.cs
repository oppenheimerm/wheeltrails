using WT.Maui.ViewModels;

namespace WT.Maui.Views;

public partial class HomePage : ContentPage
{
	public HomePage(HomeViewModel vm)
	{
		InitializeComponent();
		BindingContext = vm;
    }
}