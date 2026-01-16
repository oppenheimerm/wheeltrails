using CommunityToolkit.Mvvm.ComponentModel;

namespace WT.Maui.ViewModels
{
    public partial class BaseViewModel : ObservableObject
    {
        //  I'm going to stick to using the field‑based [ObservableProperty] pattern,

        [ObservableProperty]
        // This attribute ensures that when IsBusy changes, IsNotBusy will also notify any bindings
        [NotifyPropertyChangedFor(nameof(IsNotBusy))]
        bool isBusy;

        [ObservableProperty]
        string title;

        public bool IsNotBusy => !IsBusy;

        [ObservableProperty]
        public string errorMessage;

    }
}
