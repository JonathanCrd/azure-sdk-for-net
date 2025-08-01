// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;

namespace Azure.ResourceManager.DataMigration.Models
{
    /// <summary> Migration Validation Database level summary result. </summary>
    public partial class MigrationValidationDatabaseSummaryResult
    {
        /// <summary>
        /// Keeps track of any properties unknown to the library.
        /// <para>
        /// To assign an object to the value of this property use <see cref="BinaryData.FromObjectAsJson{T}(T, System.Text.Json.JsonSerializerOptions?)"/>.
        /// </para>
        /// <para>
        /// To assign an already formatted json string to this property use <see cref="BinaryData.FromString(string)"/>.
        /// </para>
        /// <para>
        /// Examples:
        /// <list type="bullet">
        /// <item>
        /// <term>BinaryData.FromObjectAsJson("foo")</term>
        /// <description>Creates a payload of "foo".</description>
        /// </item>
        /// <item>
        /// <term>BinaryData.FromString("\"foo\"")</term>
        /// <description>Creates a payload of "foo".</description>
        /// </item>
        /// <item>
        /// <term>BinaryData.FromObjectAsJson(new { key = "value" })</term>
        /// <description>Creates a payload of { "key": "value" }.</description>
        /// </item>
        /// <item>
        /// <term>BinaryData.FromString("{\"key\": \"value\"}")</term>
        /// <description>Creates a payload of { "key": "value" }.</description>
        /// </item>
        /// </list>
        /// </para>
        /// </summary>
        private IDictionary<string, BinaryData> _serializedAdditionalRawData;

        /// <summary> Initializes a new instance of <see cref="MigrationValidationDatabaseSummaryResult"/>. </summary>
        internal MigrationValidationDatabaseSummaryResult()
        {
        }

        /// <summary> Initializes a new instance of <see cref="MigrationValidationDatabaseSummaryResult"/>. </summary>
        /// <param name="id"> Result identifier. </param>
        /// <param name="migrationId"> Migration Identifier. </param>
        /// <param name="sourceDatabaseName"> Name of the source database. </param>
        /// <param name="targetDatabaseName"> Name of the target database. </param>
        /// <param name="startedOn"> Validation start time. </param>
        /// <param name="endedOn"> Validation end time. </param>
        /// <param name="status"> Current status of validation at the database level. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal MigrationValidationDatabaseSummaryResult(string id, string migrationId, string sourceDatabaseName, string targetDatabaseName, DateTimeOffset? startedOn, DateTimeOffset? endedOn, MigrationValidationStatus? status, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            Id = id;
            MigrationId = migrationId;
            SourceDatabaseName = sourceDatabaseName;
            TargetDatabaseName = targetDatabaseName;
            StartedOn = startedOn;
            EndedOn = endedOn;
            Status = status;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> Result identifier. </summary>
        public string Id { get; }
        /// <summary> Migration Identifier. </summary>
        public string MigrationId { get; }
        /// <summary> Name of the source database. </summary>
        public string SourceDatabaseName { get; }
        /// <summary> Name of the target database. </summary>
        public string TargetDatabaseName { get; }
        /// <summary> Validation start time. </summary>
        public DateTimeOffset? StartedOn { get; }
        /// <summary> Validation end time. </summary>
        public DateTimeOffset? EndedOn { get; }
        /// <summary> Current status of validation at the database level. </summary>
        public MigrationValidationStatus? Status { get; }
    }
}
