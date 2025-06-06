// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ComponentModel;

namespace Azure.ResourceManager.Migration.Assessment.Models
{
    /// <summary> The MigrationAssessmentOSLicense. </summary>
    public readonly partial struct MigrationAssessmentOSLicense : IEquatable<MigrationAssessmentOSLicense>
    {
        private readonly string _value;

        /// <summary> Initializes a new instance of <see cref="MigrationAssessmentOSLicense"/>. </summary>
        /// <exception cref="ArgumentNullException"> <paramref name="value"/> is null. </exception>
        public MigrationAssessmentOSLicense(string value)
        {
            _value = value ?? throw new ArgumentNullException(nameof(value));
        }

        private const string UnknownValue = "Unknown";
        private const string YesValue = "Yes";
        private const string NoValue = "No";

        /// <summary> Unknown. </summary>
        public static MigrationAssessmentOSLicense Unknown { get; } = new MigrationAssessmentOSLicense(UnknownValue);
        /// <summary> Yes. </summary>
        public static MigrationAssessmentOSLicense Yes { get; } = new MigrationAssessmentOSLicense(YesValue);
        /// <summary> No. </summary>
        public static MigrationAssessmentOSLicense No { get; } = new MigrationAssessmentOSLicense(NoValue);
        /// <summary> Determines if two <see cref="MigrationAssessmentOSLicense"/> values are the same. </summary>
        public static bool operator ==(MigrationAssessmentOSLicense left, MigrationAssessmentOSLicense right) => left.Equals(right);
        /// <summary> Determines if two <see cref="MigrationAssessmentOSLicense"/> values are not the same. </summary>
        public static bool operator !=(MigrationAssessmentOSLicense left, MigrationAssessmentOSLicense right) => !left.Equals(right);
        /// <summary> Converts a <see cref="string"/> to a <see cref="MigrationAssessmentOSLicense"/>. </summary>
        public static implicit operator MigrationAssessmentOSLicense(string value) => new MigrationAssessmentOSLicense(value);

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(object obj) => obj is MigrationAssessmentOSLicense other && Equals(other);
        /// <inheritdoc />
        public bool Equals(MigrationAssessmentOSLicense other) => string.Equals(_value, other._value, StringComparison.InvariantCultureIgnoreCase);

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => _value != null ? StringComparer.InvariantCultureIgnoreCase.GetHashCode(_value) : 0;
        /// <inheritdoc />
        public override string ToString() => _value;
    }
}
