using System;

namespace WT.Client.Services
{
    /// <summary>
    /// Actions the global Floating Action Button (FAB) can raise.
    /// Components/pages can subscribe to <see cref="IFabService.OnFabAction"/> to respond.
    /// </summary>
    public enum FabAction
    {
        /// <summary>
        /// Toggle the recording state (start/stop GPS recording) on the active page.
        /// </summary>
        ToggleRecording,

        /// <summary>
        /// Add a Point Of Interest at the current location on the active page.
        /// </summary>
        AddPoi,

        /// <summary>
        /// Submit the current trail or perform a save action on the active page.
        /// </summary>
        SubmitTrail
    }

    /// <summary>
    /// Lightweight pub/sub service used to raise FAB actions from layout-level UI down to
    /// the currently active page. Implemented as a singleton so any component can raise
    /// or subscribe to actions without tight coupling.
    /// </summary>
    public interface IFabService
    {
        /// <summary>
        /// Event raised when a FAB action occurs. Pages should subscribe to this event
        /// and handle the received <see cref="FabAction"/> accordingly.
        /// </summary>
        event Action<FabAction>? OnFabAction;

        /// <summary>
        /// Raise a FAB action. This invokes <see cref="OnFabAction"/> for all subscribers.
        /// </summary>
        /// <param name="action">The action to raise.</param>
        void Raise(FabAction action);
    }
}
