using WT.Maui.ViewModels;

namespace WT.Maui.Views.Trails;

public partial class Create : ContentPage
{
    private readonly CreateTrailViewModel _vm;

    public Create(CreateTrailViewModel vm)
    {
        InitializeComponent();
        BindingContext = vm;
        _vm = vm;
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        // Fire-and-forget: try to populate a cached last-known location silently.
        _ = _vm.TryUseLastKnownLocationAsync();
    }
}