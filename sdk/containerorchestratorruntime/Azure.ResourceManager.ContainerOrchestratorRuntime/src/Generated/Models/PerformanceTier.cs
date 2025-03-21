// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ComponentModel;

namespace Azure.ResourceManager.ContainerOrchestratorRuntime.Models
{
    /// <summary> Performance tier of a storage class. </summary>
    public readonly partial struct PerformanceTier : IEquatable<PerformanceTier>
    {
        private readonly string _value;

        /// <summary> Initializes a new instance of <see cref="PerformanceTier"/>. </summary>
        /// <exception cref="ArgumentNullException"> <paramref name="value"/> is null. </exception>
        public PerformanceTier(string value)
        {
            _value = value ?? throw new ArgumentNullException(nameof(value));
        }

        private const string UndefinedValue = "Undefined";
        private const string BasicValue = "Basic";
        private const string StandardValue = "Standard";
        private const string PremiumValue = "Premium";
        private const string UltraValue = "Ultra";

        /// <summary> Undefined Performance Tier. </summary>
        public static PerformanceTier Undefined { get; } = new PerformanceTier(UndefinedValue);
        /// <summary> Basic Performance Tier. </summary>
        public static PerformanceTier Basic { get; } = new PerformanceTier(BasicValue);
        /// <summary> Standard Performance Tier. </summary>
        public static PerformanceTier Standard { get; } = new PerformanceTier(StandardValue);
        /// <summary> Premium Performance Tier. </summary>
        public static PerformanceTier Premium { get; } = new PerformanceTier(PremiumValue);
        /// <summary> Ultra Performance Tier. </summary>
        public static PerformanceTier Ultra { get; } = new PerformanceTier(UltraValue);
        /// <summary> Determines if two <see cref="PerformanceTier"/> values are the same. </summary>
        public static bool operator ==(PerformanceTier left, PerformanceTier right) => left.Equals(right);
        /// <summary> Determines if two <see cref="PerformanceTier"/> values are not the same. </summary>
        public static bool operator !=(PerformanceTier left, PerformanceTier right) => !left.Equals(right);
        /// <summary> Converts a <see cref="string"/> to a <see cref="PerformanceTier"/>. </summary>
        public static implicit operator PerformanceTier(string value) => new PerformanceTier(value);

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(object obj) => obj is PerformanceTier other && Equals(other);
        /// <inheritdoc />
        public bool Equals(PerformanceTier other) => string.Equals(_value, other._value, StringComparison.InvariantCultureIgnoreCase);

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => _value != null ? StringComparer.InvariantCultureIgnoreCase.GetHashCode(_value) : 0;
        /// <inheritdoc />
        public override string ToString() => _value;
    }
}
