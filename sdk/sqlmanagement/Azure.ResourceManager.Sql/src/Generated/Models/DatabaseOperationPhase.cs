// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ComponentModel;

namespace Azure.ResourceManager.Sql.Models
{
    /// <summary> The operation phase. </summary>
    public readonly partial struct DatabaseOperationPhase : IEquatable<DatabaseOperationPhase>
    {
        private readonly string _value;

        /// <summary> Initializes a new instance of <see cref="DatabaseOperationPhase"/>. </summary>
        /// <exception cref="ArgumentNullException"> <paramref name="value"/> is null. </exception>
        public DatabaseOperationPhase(string value)
        {
            _value = value ?? throw new ArgumentNullException(nameof(value));
        }
        private const string CopyingValue = "Copying";
        private const string CatchupValue = "Catchup";
        private const string WaitingForCutoverValue = "WaitingForCutover";
        private const string CutoverInProgressValue = "CutoverInProgress";
        /// <summary> Copying. </summary>
        public static DatabaseOperationPhase Copying { get; } = new DatabaseOperationPhase(CopyingValue);
        /// <summary> Catchup. </summary>
        public static DatabaseOperationPhase Catchup { get; } = new DatabaseOperationPhase(CatchupValue);
        /// <summary> WaitingForCutover. </summary>
        public static DatabaseOperationPhase WaitingForCutover { get; } = new DatabaseOperationPhase(WaitingForCutoverValue);
        /// <summary> CutoverInProgress. </summary>
        public static DatabaseOperationPhase CutoverInProgress { get; } = new DatabaseOperationPhase(CutoverInProgressValue);
        /// <summary> Determines if two <see cref="DatabaseOperationPhase"/> values are the same. </summary>
        public static bool operator ==(DatabaseOperationPhase left, DatabaseOperationPhase right) => left.Equals(right);
        /// <summary> Determines if two <see cref="DatabaseOperationPhase"/> values are not the same. </summary>
        public static bool operator !=(DatabaseOperationPhase left, DatabaseOperationPhase right) => !left.Equals(right);
        /// <summary> Converts a <see cref="string"/> to a <see cref="DatabaseOperationPhase"/>. </summary>
        public static implicit operator DatabaseOperationPhase(string value) => new DatabaseOperationPhase(value);

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(object obj) => obj is DatabaseOperationPhase other && Equals(other);
        /// <inheritdoc />
        public bool Equals(DatabaseOperationPhase other) => string.Equals(_value, other._value, StringComparison.InvariantCultureIgnoreCase);

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => _value != null ? StringComparer.InvariantCultureIgnoreCase.GetHashCode(_value) : 0;
        /// <inheritdoc />
        public override string ToString() => _value;
    }
}
