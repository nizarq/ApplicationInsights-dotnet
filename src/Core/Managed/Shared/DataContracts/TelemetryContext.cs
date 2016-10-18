namespace Microsoft.ApplicationInsights.DataContracts
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.Text;
    using System.Threading;
    using Microsoft.ApplicationInsights.Channel;
    using Microsoft.ApplicationInsights.Extensibility;
    using Microsoft.ApplicationInsights.Extensibility.Implementation;

    /// <summary>
    /// Represents a context for sending telemetry to the Application Insights service.
    /// </summary>
    public sealed class TelemetryContext
    {
        private readonly IDictionary<string, string> properties;
        private readonly IDictionary<string, string> tags;

        private string instrumentationKey;
        private string instrumentationKeyHash;

        private ComponentContext component;
        private DeviceContext device;
        private CloudContext cloud;
        private SessionContext session;
        private UserContext user;
        private OperationContext operation;
        private LocationContext location;
        private InternalContext internalContext;

        /// <summary>
        /// Initializes a new instance of the <see cref="TelemetryContext"/> class.
        /// </summary>
        public TelemetryContext()
            : this(new ConcurrentDictionary<string, string>())
        {
        }

        internal TelemetryContext(IDictionary<string, string> properties)
        {
            Debug.Assert(properties != null, "properties");
            this.properties = properties;
            this.tags = new ConcurrentDictionary<string, string>();
        }

        /// <summary>
        /// Gets or sets the default instrumentation key for all <see cref="ITelemetry"/> objects logged in this <see cref="TelemetryContext"/>.
        /// </summary>
        /// <remarks>
        /// By default, this property is initialized with the <see cref="TelemetryConfiguration.InstrumentationKey"/> value
        /// of the <see cref="TelemetryConfiguration.Active"/> instance of <see cref="TelemetryConfiguration"/>. You can specify it 
        /// for all telemetry tracked via a particular <see cref="TelemetryClient"/> or for a specific <see cref="ITelemetry"/> 
        /// instance.
        /// </remarks>
        public string InstrumentationKey
        {
            get
            {
                return this.instrumentationKey ?? string.Empty;
            }

            set
            {
                Property.Set(ref this.instrumentationKey, value);
                Property.Set(ref this.instrumentationKeyHash, GenerateSHA256Hash(value));
            }
        }

        /// <summary>
        /// Gets the hash for the instrumentation key.
        /// </summary>
        public string InstrumentationKeyHash
        {
            get { return this.instrumentationKeyHash ?? string.Empty; }
        }

        /// <summary>
        /// Gets the object describing the component tracked by this <see cref="TelemetryContext"/>.
        /// </summary>
        public ComponentContext Component
        {
            get { return LazyInitializer.EnsureInitialized(ref this.component, () => new ComponentContext(this.Tags)); }
        }

        /// <summary>
        /// Gets the object describing the device tracked by this <see cref="TelemetryContext"/>.
        /// </summary>
        public DeviceContext Device
        {
            get { return LazyInitializer.EnsureInitialized(ref this.device, () => new DeviceContext(this.Tags, this.Properties)); }
        }

        /// <summary>
        /// Gets the object describing the cloud tracked by this <see cref="TelemetryContext"/>.
        /// </summary>
        public CloudContext Cloud
        {
            get { return LazyInitializer.EnsureInitialized(ref this.cloud, () => new CloudContext(this.Tags)); }
        }

        /// <summary>
        /// Gets the object describing a user session tracked by this <see cref="TelemetryContext"/>.
        /// </summary>
        public SessionContext Session
        {
            get { return LazyInitializer.EnsureInitialized(ref this.session, () => new SessionContext(this.Tags)); }
        }

        /// <summary>
        /// Gets the object describing a user tracked by this <see cref="TelemetryContext"/>.
        /// </summary>
        public UserContext User
        {
            get { return LazyInitializer.EnsureInitialized(ref this.user, () => new UserContext(this.Tags)); }
        }

        /// <summary>
        /// Gets the object describing a operation tracked by this <see cref="TelemetryContext"/>.
        /// </summary>
        public OperationContext Operation
        {
            get { return LazyInitializer.EnsureInitialized(ref this.operation, () => new OperationContext(this.Tags)); }
        }

        /// <summary>
        /// Gets the object describing a location tracked by this <see cref="TelemetryContext" />.
        /// </summary>
        public LocationContext Location
        {
            get { return LazyInitializer.EnsureInitialized(ref this.location, () => new LocationContext(this.Tags)); }
        }

        /// <summary>
        /// Gets a dictionary of application-defined property values.
        /// </summary>
        public IDictionary<string, string> Properties
        {
            get { return this.properties; }
        }

        internal InternalContext Internal
        {
            get { return LazyInitializer.EnsureInitialized(ref this.internalContext, () => new InternalContext(this.Tags)); }
        }

        /// <summary>
        /// Gets a dictionary of context tags.
        /// </summary>
        internal IDictionary<string, string> Tags
        {
            get { return this.tags; }
        }

        internal void Initialize(TelemetryContext source, string instrumentationKey)
        {
            Property.Initialize(ref this.instrumentationKey, instrumentationKey);

            if (source.tags != null && source.tags.Count > 0)
            {
                Utils.CopyDictionary(source.tags, this.Tags);
            }
        }

        /// <summary>
        /// Computes the SHA256 hash for a given value.
        /// </summary>
        /// <param name="value">Value for which the hash is to be computed.</param>
        /// <returns>Hash string.</returns>
        private static string GenerateSHA256Hash(string value)
        {
            string hashString = string.Empty;

#if CORE_PCL
            var hasher = PCLCrypto.WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(PCLCrypto.HashAlgorithm.Sha1);
            byte[] hash = hasher.HashData(Encoding.UTF8.GetBytes(value));
#else
            var sha256 = System.Security.Cryptography.SHA256Managed.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(value));
#endif

            foreach (byte x in hash)
            {
                hashString += string.Format(CultureInfo.InvariantCulture, "{0:x2}", x);
            }

            return hashString;
        }
    }
}