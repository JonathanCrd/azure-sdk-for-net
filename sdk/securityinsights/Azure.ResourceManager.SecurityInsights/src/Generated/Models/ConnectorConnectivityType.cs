// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ComponentModel;

namespace Azure.ResourceManager.SecurityInsights.Models
{
    /// <summary> type of connectivity. </summary>
    public readonly partial struct ConnectorConnectivityType : IEquatable<ConnectorConnectivityType>
    {
        private readonly string _value;

        /// <summary> Initializes a new instance of <see cref="ConnectorConnectivityType"/>. </summary>
        /// <exception cref="ArgumentNullException"> <paramref name="value"/> is null. </exception>
        public ConnectorConnectivityType(string value)
        {
            _value = value ?? throw new ArgumentNullException(nameof(value));
        }

        private const string IsConnectedQueryValue = "IsConnectedQuery";

        /// <summary> IsConnectedQuery. </summary>
        public static ConnectorConnectivityType IsConnectedQuery { get; } = new ConnectorConnectivityType(IsConnectedQueryValue);
        /// <summary> Determines if two <see cref="ConnectorConnectivityType"/> values are the same. </summary>
        public static bool operator ==(ConnectorConnectivityType left, ConnectorConnectivityType right) => left.Equals(right);
        /// <summary> Determines if two <see cref="ConnectorConnectivityType"/> values are not the same. </summary>
        public static bool operator !=(ConnectorConnectivityType left, ConnectorConnectivityType right) => !left.Equals(right);
        /// <summary> Converts a string to a <see cref="ConnectorConnectivityType"/>. </summary>
        public static implicit operator ConnectorConnectivityType(string value) => new ConnectorConnectivityType(value);

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(object obj) => obj is ConnectorConnectivityType other && Equals(other);
        /// <inheritdoc />
        public bool Equals(ConnectorConnectivityType other) => string.Equals(_value, other._value, StringComparison.InvariantCultureIgnoreCase);

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => _value != null ? StringComparer.InvariantCultureIgnoreCase.GetHashCode(_value) : 0;
        /// <inheritdoc />
        public override string ToString() => _value;
    }
}
