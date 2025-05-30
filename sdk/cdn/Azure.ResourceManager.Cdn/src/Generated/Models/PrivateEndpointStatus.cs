// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ComponentModel;

namespace Azure.ResourceManager.Cdn.Models
{
    /// <summary>
    /// The approval status for the connection to the Private Link
    /// Serialized Name: PrivateEndpointStatus
    /// </summary>
    public readonly partial struct PrivateEndpointStatus : IEquatable<PrivateEndpointStatus>
    {
        private readonly string _value;

        /// <summary> Initializes a new instance of <see cref="PrivateEndpointStatus"/>. </summary>
        /// <exception cref="ArgumentNullException"> <paramref name="value"/> is null. </exception>
        public PrivateEndpointStatus(string value)
        {
            _value = value ?? throw new ArgumentNullException(nameof(value));
        }

        private const string PendingValue = "Pending";
        private const string ApprovedValue = "Approved";
        private const string RejectedValue = "Rejected";
        private const string DisconnectedValue = "Disconnected";
        private const string TimeoutValue = "Timeout";

        /// <summary>
        /// Pending
        /// Serialized Name: PrivateEndpointStatus.Pending
        /// </summary>
        public static PrivateEndpointStatus Pending { get; } = new PrivateEndpointStatus(PendingValue);
        /// <summary>
        /// Approved
        /// Serialized Name: PrivateEndpointStatus.Approved
        /// </summary>
        public static PrivateEndpointStatus Approved { get; } = new PrivateEndpointStatus(ApprovedValue);
        /// <summary>
        /// Rejected
        /// Serialized Name: PrivateEndpointStatus.Rejected
        /// </summary>
        public static PrivateEndpointStatus Rejected { get; } = new PrivateEndpointStatus(RejectedValue);
        /// <summary>
        /// Disconnected
        /// Serialized Name: PrivateEndpointStatus.Disconnected
        /// </summary>
        public static PrivateEndpointStatus Disconnected { get; } = new PrivateEndpointStatus(DisconnectedValue);
        /// <summary>
        /// Timeout
        /// Serialized Name: PrivateEndpointStatus.Timeout
        /// </summary>
        public static PrivateEndpointStatus Timeout { get; } = new PrivateEndpointStatus(TimeoutValue);
        /// <summary> Determines if two <see cref="PrivateEndpointStatus"/> values are the same. </summary>
        public static bool operator ==(PrivateEndpointStatus left, PrivateEndpointStatus right) => left.Equals(right);
        /// <summary> Determines if two <see cref="PrivateEndpointStatus"/> values are not the same. </summary>
        public static bool operator !=(PrivateEndpointStatus left, PrivateEndpointStatus right) => !left.Equals(right);
        /// <summary> Converts a <see cref="string"/> to a <see cref="PrivateEndpointStatus"/>. </summary>
        public static implicit operator PrivateEndpointStatus(string value) => new PrivateEndpointStatus(value);

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(object obj) => obj is PrivateEndpointStatus other && Equals(other);
        /// <inheritdoc />
        public bool Equals(PrivateEndpointStatus other) => string.Equals(_value, other._value, StringComparison.InvariantCultureIgnoreCase);

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => _value != null ? StringComparer.InvariantCultureIgnoreCase.GetHashCode(_value) : 0;
        /// <inheritdoc />
        public override string ToString() => _value;
    }
}
