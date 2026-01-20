using WT.Maui.ViewModels;

namespace WT.Maui.Views.Trails;

public partial class Create : ContentPage
{
    public Create(CreateTrailViewModel vm)
    {
        InitializeComponent();
        BindingContext = vm;
    }
}