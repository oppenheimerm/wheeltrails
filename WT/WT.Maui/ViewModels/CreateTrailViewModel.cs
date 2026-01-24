using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Maui.ApplicationModel;
using WT.Application.DTO.Request.Trail;
using WT.Domain.Enums;
using WT.Domain.Geo;
using WT.Maui.Services;

namespace WT.Maui.ViewModels
{
    public partial class CreateTrailViewModel : BaseViewModel
    {
        private readonly TrailService _trailService;
        private CancellationTokenSource? _cts;

        // Trail metadata
        [ObservableProperty]
        [NotifyCanExecuteChangedFor(nameof(SubmitTrailCommand))]
        private string title = string.Empty;

        [ObservableProperty]
        private string description = string.Empty;

        [ObservableProperty]
        private TrailDifficulty selectedDifficulty = TrailDifficulty.Easy;

        // Surface type flags
        [ObservableProperty]
        private bool isPavedSelected = true;

        [ObservableProperty]
        private bool isGrassSelected;

        [ObservableProperty]
        private bool isGravelSelected;

        [ObservableProperty]
        private bool isBoardwalkSelected;

        [ObservableProperty]
        private bool isRoadSelected;

        [ObservableProperty]
        private bool isDirtSelected;

        [ObservableProperty]
        private bool isRubberSelected;

        // Recording state
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(RecordingButtonText))]
        [NotifyPropertyChangedFor(nameof(RecordingButtonColor))]
        [NotifyPropertyChangedFor(nameof(CanAddPoi))]
        [NotifyPropertyChangedFor(nameof(CanStartRecording))]
        [NotifyPropertyChangedFor(nameof(CanToggleRecording))]
        [NotifyCanExecuteChangedFor(nameof(SubmitTrailCommand))]
        private bool isRecording;

        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(CanStartRecording))]
        [NotifyPropertyChangedFor(nameof(CanToggleRecording))]
        private bool isSubmitting;

        // Location data
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(LastPositionDisplay))]
        [NotifyPropertyChangedFor(nameof(CanAddPoi))]
        [NotifyPropertyChangedFor(nameof(CanStartRecording))]
        [NotifyPropertyChangedFor(nameof(CanToggleRecording))]
        private WTLatLng? lastKnownPosition;

        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(AltitudeDisplay))]
        private double? lastAltitude;

        // Waypoints and POIs
        public ObservableCollection<WTLatLng> Waypoints { get; } = new ObservableCollection<WTLatLng>();
        public ObservableCollection<WTPointOfInterest> PointsOfInterest { get; } = new ObservableCollection<WTPointOfInterest>();

        // Timing
        private DateTime? timeStart;
        private TimeSpan timeAccumulated = TimeSpan.Zero;
        private IDispatcherTimer? elapsedTimer;

        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(ElapsedTimeDisplay))]
        private TimeSpan elapsedTime;

        // Success message
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(HasSuccess))]
        private string successMessage = string.Empty;

        // Computed properties
        public int WaypointCount => Waypoints.Count;
        public int PoiCount => PointsOfInterest.Count;

        public string LastPositionDisplay => LastKnownPosition is null
            ? "N/A"
            : $"{LastKnownPosition.Lat:F5}, {LastKnownPosition.Lng:F5}";

        public string AltitudeDisplay => LastAltitude.HasValue
            ? $"{LastAltitude.Value:F1} m"
            : "N/A";

        public string ElapsedTimeDisplay
        {
            get
            {
                var ts = ElapsedTime;
                return ts.TotalHours >= 1
                    ? $"{(int)ts.TotalHours}:{ts.Minutes:00}:{ts.Seconds:00}"
                    : $"{(int)ts.TotalMinutes:00}:{ts.Seconds:00}";
            }
        }

        public string DistanceDisplay
        {
            get
            {
                var meters = CalculateTotalDistance();
                return meters >= 1000
                    ? $"{meters / 1000:F2} km"
                    : $"{meters:F0} m";
            }
        }

        public string RecordingButtonText => IsRecording ? "Stop Recording" : "Start Recording";

        public Color RecordingButtonColor => IsRecording
            ? Colors.Red
            : Color.FromArgb("#4CAF50");

        public bool CanAddPoi => IsRecording && LastKnownPosition is not null;

        // New computed properties used to enable/disable recording affordances
        public bool CanStartRecording => !IsRecording && !IsSubmitting && LastKnownPosition is not null;
        public bool CanToggleRecording => IsRecording || CanStartRecording;

        public bool CanSubmit => !IsRecording && !IsSubmitting && Waypoints.Count >= 2 && !string.IsNullOrWhiteSpace(Title);

        public string SubmitButtonText => IsSubmitting ? "Submitting..." : "Submit Trail";

        public bool HasError => !string.IsNullOrEmpty(ErrorMessage);
        public bool HasSuccess => !string.IsNullOrEmpty(SuccessMessage);

        // Difficulty options for picker
        public List<TrailDifficulty> DifficultyOptions { get; } =
        new()
        {
            TrailDifficulty.Easy,
            TrailDifficulty.Moderate,
            TrailDifficulty.Challenging,
            TrailDifficulty.VeryDifficult
        };

        // Inject TrailService so ViewModel can submit to API (no extra UI needed)
        public CreateTrailViewModel(TrailService trailService)
        {
            _trailService = trailService ?? throw new ArgumentNullException(nameof(trailService));

            Waypoints.CollectionChanged += (_, _) =>
            {
                OnPropertyChanged(nameof(WaypointCount));
                OnPropertyChanged(nameof(DistanceDisplay));
                OnPropertyChanged(nameof(CanSubmit));
            };

            PointsOfInterest.CollectionChanged += (_, _) =>
            {
                OnPropertyChanged(nameof(PoiCount));
            };
        }

        /// <summary>
        /// Try to silently use the device's last known location when the view appears.
        /// This avoids prompting the permission dialog immediately and gives the UI a cached fix if available.
        /// </summary>
        public async Task TryUseLastKnownLocationAsync()
        {
            try
            {
                var location = await Geolocation.Default.GetLastKnownLocationAsync();
                if (location is not null)
                {
                    LastKnownPosition = new WTLatLng(location.Latitude, location.Longitude, location.Altitude, DateTime.UtcNow);
                    LastAltitude = location.Altitude;
                    // No success message to avoid surprising the user — it's a silent seed.
                }
            }
            catch
            {
                // Ignore failures silently; don't surface permission prompts here.
            }
        }

        [RelayCommand]
        private async Task ToggleRecordingAsync()
        {
            if (!IsRecording)
            {
                await StartRecordingAsync();
            }
            else
            {
                await StopRecordingAsync();
            }
        }

        private async Task StartRecordingAsync()
        {
            ErrorMessage = string.Empty;
            SuccessMessage = string.Empty;

            // If we don't already have a fix, attempt a one-time acquisition so Start Recording is a single action.
            if (LastKnownPosition is null)
            {
                await GetCurrentLocationAsync();
                if (LastKnownPosition is null)
                {
                    // GetCurrentLocationAsync will have set an error message if it failed/was denied.
                    return;
                }
            }

            // Request location permission (if not already granted by the previous call)
            var status = await Permissions.CheckStatusAsync<Permissions.LocationWhenInUse>();
            if (status != PermissionStatus.Granted)
            {
                status = await Permissions.RequestAsync<Permissions.LocationWhenInUse>();
                if (status != PermissionStatus.Granted)
                {
                    ErrorMessage = "Location permission is required to record trails.";
                    return;
                }
            }

            // Clear previous data if starting fresh
            if (timeAccumulated == TimeSpan.Zero)
            {
                Waypoints.Clear();
                PointsOfInterest.Clear();
            }

            IsRecording = true;
            timeStart = DateTime.UtcNow;

            // Start elapsed time timer
            elapsedTimer = Microsoft.Maui.Controls.Application.Current?.Dispatcher.CreateTimer();
            if (elapsedTimer is not null)
            {
                elapsedTimer.Interval = TimeSpan.FromSeconds(1);
                elapsedTimer.Tick += (s, e) => UpdateElapsedTime();
                elapsedTimer.Start();
            }

            // Start location tracking in background so the ToggleRecording command can complete.
            _ = Task.Run(async () =>
            {
                try
                {
                    await StartLocationTrackingAsync();
                }
                catch (Exception ex)
                {
                    Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
                    {
                        ErrorMessage = $"Location tracking failed: {ex.Message}";
                        IsRecording = false;
                    });
                }
            });
        }

        private async Task StopRecordingAsync()
        {
            IsRecording = false;

            // Stop elapsed timer
            elapsedTimer?.Stop();
            elapsedTimer = null;

            // Accumulate elapsed time
            if (timeStart.HasValue)
            {
                timeAccumulated += DateTime.UtcNow - timeStart.Value;
                timeStart = null;
            }

            // Stop location tracking: the background loop in StartLocationTrackingAsync observes IsRecording and will exit.
            await Task.CompletedTask;

            OnPropertyChanged(nameof(CanSubmit));
        }

        private void UpdateElapsedTime()
        {
            if (timeStart.HasValue)
            {
                ElapsedTime = timeAccumulated + (DateTime.UtcNow - timeStart.Value);
            }
        }

        private async Task StartLocationTrackingAsync()
        {
            try
            {
                var request = new GeolocationRequest(GeolocationAccuracy.Best, TimeSpan.FromSeconds(10));

                while (IsRecording)
                {
                    var location = await Geolocation.Default.GetLocationAsync(request);
                    if (location is not null)
                    {
                        var point = new WTLatLng(location.Latitude, location.Longitude, location.Altitude, DateTime.UtcNow);
                        LastKnownPosition = point;
                        LastAltitude = location.Altitude;

                        Waypoints.Add(point);

                        if (location.Altitude.HasValue)
                        {
                            // Elevation data tracked implicitly via LastAltitude
                        }

                        OnPropertyChanged(nameof(DistanceDisplay));
                    }

                    await Task.Delay(TimeSpan.FromSeconds(3));
                }
            }
            catch (FeatureNotSupportedException)
            {
                ErrorMessage = "Geolocation is not supported on this device.";
                IsRecording = false;
            }
            catch (FeatureNotEnabledException)
            {
                ErrorMessage = "Please enable location services.";
                IsRecording = false;
            }
            catch (PermissionException)
            {
                ErrorMessage = "Location permission denied.";
                IsRecording = false;
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error getting location: {ex.Message}";
                IsRecording = false;
            }
        }

        [RelayCommand]
        private async Task GetCurrentLocationAsync()
        {
            try
            {
                IsBusy = true;
                ErrorMessage = string.Empty;

                var status = await Permissions.CheckStatusAsync<Permissions.LocationWhenInUse>();
                if (status != PermissionStatus.Granted)
                {
                    status = await Permissions.RequestAsync<Permissions.LocationWhenInUse>();
                    if (status != PermissionStatus.Granted)
                    {
                        ErrorMessage = "Location permission is required.";
                        return;
                    }
                }

                var request = new GeolocationRequest(GeolocationAccuracy.Best, TimeSpan.FromSeconds(10));
                var location = await Geolocation.Default.GetLocationAsync(request);

                if (location is not null)
                {
                    LastKnownPosition = new WTLatLng(location.Latitude, location.Longitude, location.Altitude, DateTime.UtcNow);
                    LastAltitude = location.Altitude;
                    SuccessMessage = $"Location acquired: {LastPositionDisplay}";
                }
                else
                {
                    ErrorMessage = "Unable to get current location.";
                }
            }
            catch (FeatureNotSupportedException)
            {
                ErrorMessage = "Geolocation is not supported on this device.";
            }
            catch (FeatureNotEnabledException)
            {
                ErrorMessage = "Please enable location services.";
            }
            catch (PermissionException)
            {
                ErrorMessage = "Location permission denied.";
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error: {ex.Message}";
            }
            finally
            {
                IsBusy = false;
            }
        }

        [RelayCommand]
        private void AddPoi()
        {
            if (LastKnownPosition is null) return;

            var poi = new WTPointOfInterest(LastKnownPosition, "VIEW", string.Empty);
            PointsOfInterest.Add(poi);
            SuccessMessage = "Point of Interest added.";
        }

        [RelayCommand(CanExecute = nameof(CanSubmit))]
        private async Task SubmitTrailAsync()
        {
            if (Waypoints.Count < 2)
            {
                ErrorMessage = "Please record at least two points (start and end) before submitting.";
                return;
            }

            try
            {
                IsSubmitting = true;
                ErrorMessage = string.Empty;
                SuccessMessage = string.Empty;

                // Prepare DTO
                var trail = new CreateTrailDTO
                {
                    Title = Title,
                    Description = Description,
                    Start = Waypoints.First(),
                    End = Waypoints.Last(),
                    Waypoints = new List<WTLatLng>(Waypoints),
                    PointsOfInterest = new List<WTPointOfInterest>(PointsOfInterest),
                    Difficulty = SelectedDifficulty,
                    SurfaceTypes = GetSelectedSurfaceTypes(),
                    LengthMeters = CalculateTotalDistance(),
                    ElevationProfile = new List<double>() // TODO: Collect elevation data
                };

                // Create a cancellation token for this submission
                try
                {
                    _cts?.Dispose();
                }
                catch { /* ignore */ }
                _cts = new CancellationTokenSource();

                // Call real API via TrailService
                var response = await _trailService.CreateTrailAsync(trail, _cts.Token);

                if (response.Success)
                {
                    SuccessMessage = $"Trail '{response.Trail?.Title ?? trail.Title}' created successfully!";
                    // Reset form after successful submission
                    ResetForm();
                }
                else
                {
                    ErrorMessage = response.Message ?? "Failed to create trail. Please try again.";
                }
            }
            catch (OperationCanceledException)
            {
                ErrorMessage = "Trail submission was cancelled.";
            }
            catch (HttpRequestException ex)
            {
                ErrorMessage = "Network error. Please check your connection and try again.";
                Console.WriteLine($"Network error in SubmitTrailAsync: {ex.Message}");
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Failed to submit trail: {ex.Message}";
                Console.WriteLine($"Error in SubmitTrailAsync: {ex}");
            }
            finally
            {
                IsSubmitting = false;
                OnPropertyChanged(nameof(CanSubmit));
            }
        }

        /// <summary>
        /// Dev helper: programmatic submission to API using registered TrailService.
        /// No UI button required — call this method when you want to send the recorded trail to the API.
        /// </summary>
        public async Task SendDevSubmissionAsync()
        {
            ErrorMessage = string.Empty;
            SuccessMessage = string.Empty;

            if (IsSubmitting) return;

            if (Waypoints.Count < 2)
            {
                ErrorMessage = "No trail data to send. Record at least two waypoints first.";
                return;
            }

            try
            {
                IsSubmitting = true;
                _cts = new CancellationTokenSource();

                var trail = new CreateTrailDTO
                {
                    Title = string.IsNullOrWhiteSpace(Title) ? "Dev Recorded Trail" : Title,
                    Description = string.IsNullOrWhiteSpace(Description) ? "Dev submission of recorded trail" : Description,
                    Start = Waypoints.First(),
                    End = Waypoints.Last(),
                    Waypoints = new List<WTLatLng>(Waypoints),
                    PointsOfInterest = new List<WTPointOfInterest>(PointsOfInterest),
                    Difficulty = SelectedDifficulty,
                    SurfaceTypes = GetSelectedSurfaceTypes(),
                    LengthMeters = CalculateTotalDistance(),
                    ElevationProfile = new List<double>()
                };

                var response = await _trailService.CreateTrailAsync(trail, _cts.Token);

                if (response.Success)
                {
                    SuccessMessage = $"Dev submission saved: {response.Trail?.Title ?? trail.Title}";
                    // Optionally clear the form on success:
                    ResetForm();
                }
                else
                {
                    ErrorMessage = response.Message ?? "Dev submission failed.";
                }
            }
            catch (OperationCanceledException)
            {
                ErrorMessage = "Dev submission cancelled.";
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error sending dev submission: {ex.Message}";
            }
            finally
            {
                try { _cts?.Dispose(); } catch { }
                _cts = null;
                IsSubmitting = false;
                OnPropertyChanged(nameof(CanSubmit));
            }
        }

        public void CancelDevSubmission()
        {
            try
            {
                _cts?.Cancel();
            }
            catch { }
        }

        private SurfaceType GetSelectedSurfaceTypes()
        {
            var surfaceType = SurfaceType.None;

            if (IsPavedSelected) surfaceType |= SurfaceType.Paved;
            if (IsGrassSelected) surfaceType |= SurfaceType.Grass;
            if (IsGravelSelected) surfaceType |= SurfaceType.Gravel;
            if (IsBoardwalkSelected) surfaceType |= SurfaceType.Boardwalk;
            if (IsRoadSelected) surfaceType |= SurfaceType.Road;
            if (IsDirtSelected) surfaceType |= SurfaceType.Dirt;
            if (IsRubberSelected) surfaceType |= SurfaceType.Rubber;

            return surfaceType;
        }

        private double CalculateTotalDistance()
        {
            if (Waypoints.Count < 2) return 0;

            double totalMeters = 0;
            for (int i = 0; i < Waypoints.Count - 1; i++)
            {
                totalMeters += CalculateDistance(Waypoints[i], Waypoints[i + 1]);
            }
            return totalMeters;
        }

        private static double CalculateDistance(WTLatLng point1, WTLatLng point2)
        {
            const double R = 6371000; // Earth's radius in meters
            var lat1Rad = point1.Lat * Math.PI / 180;
            var lat2Rad = point2.Lat * Math.PI / 180;
            var deltaLat = (point2.Lat - point1.Lat) * Math.PI / 180;
            var deltaLng = (point2.Lng - point1.Lng) * Math.PI / 180;

            var a = Math.Sin(deltaLat / 2) * Math.Sin(deltaLat / 2) +
                    Math.Cos(lat1Rad) * Math.Cos(lat2Rad) *
                    Math.Sin(deltaLng / 2) * Math.Sin(deltaLng / 2);
            var c = 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));

            return R * c;
        }

        private void ResetForm()
        {
            Title = string.Empty;
            Description = string.Empty;
            SelectedDifficulty = TrailDifficulty.Easy;
            IsPavedSelected = true;
            IsGrassSelected = false;
            IsGravelSelected = false;
            IsBoardwalkSelected = false;
            IsRoadSelected = false;
            IsDirtSelected = false;
            IsRubberSelected = false;
            Waypoints.Clear();
            PointsOfInterest.Clear();
            LastKnownPosition = null;
            LastAltitude = null;
            timeAccumulated = TimeSpan.Zero;
            ElapsedTime = TimeSpan.Zero;
            OnPropertyChanged(nameof(CanSubmit));
        }
    }
}
