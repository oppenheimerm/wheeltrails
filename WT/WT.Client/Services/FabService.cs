using System;

namespace WT.Client.Services
{
    /// <summary>
    /// Default implementation of <see cref="IFabService"/>. Simple event-based
    /// pub/sub that allows layout-level FAB controls to notify pages about actions.
    ///
    /// This service is registered as a singleton so the layout and any page can
    /// share the same instance.
    /// </summary>
    public class FabService : IFabService
    {
        /// <inheritdoc />
        public event Action<FabAction>? OnFabAction;

        /// <inheritdoc />
        public event Action<bool>? OnVisibilityChanged;

        private bool _visible = false;

        /// <summary>
        /// Raises the specified <see cref="FabAction"/> to all subscribers.
        /// </summary>
        /// <param name="action">The action to raise.</param>
        public void Raise(FabAction action)
        {
            OnFabAction?.Invoke(action);
        }

        /// <inheritdoc />
        public void Show()
        {
            if (!_visible)
            {
                _visible = true;
                OnVisibilityChanged?.Invoke(true);
            }
        }

        /// <inheritdoc />
        public void Hide()
        {
            if (_visible)
            {
                _visible = false;
                OnVisibilityChanged?.Invoke(false);
            }
        }

        /// <inheritdoc />
        public void ToggleVisibility()
        {
            _visible = !_visible;
            OnVisibilityChanged?.Invoke(_visible);
        }
    }
}
