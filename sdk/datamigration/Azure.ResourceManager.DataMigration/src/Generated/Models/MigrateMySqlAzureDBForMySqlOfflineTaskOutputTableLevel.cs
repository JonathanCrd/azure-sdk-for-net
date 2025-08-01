// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;

namespace Azure.ResourceManager.DataMigration.Models
{
    /// <summary> The MigrateMySqlAzureDBForMySqlOfflineTaskOutputTableLevel. </summary>
    public partial class MigrateMySqlAzureDBForMySqlOfflineTaskOutputTableLevel : MigrateMySqlAzureDBForMySqlOfflineTaskOutput
    {
        /// <summary> Initializes a new instance of <see cref="MigrateMySqlAzureDBForMySqlOfflineTaskOutputTableLevel"/>. </summary>
        internal MigrateMySqlAzureDBForMySqlOfflineTaskOutputTableLevel()
        {
            ResultType = "TableLevelOutput";
        }

        /// <summary> Initializes a new instance of <see cref="MigrateMySqlAzureDBForMySqlOfflineTaskOutputTableLevel"/>. </summary>
        /// <param name="id"> Result identifier. </param>
        /// <param name="resultType"> Result type. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        /// <param name="objectName"> Name of the item. </param>
        /// <param name="startedOn"> Migration start time. </param>
        /// <param name="endedOn"> Migration end time. </param>
        /// <param name="state"> Current state of migration. </param>
        /// <param name="statusMessage"> Status message. </param>
        /// <param name="itemsCount"> Number of items. </param>
        /// <param name="itemsCompletedCount"> Number of successfully completed items. </param>
        /// <param name="errorPrefix"> Wildcard string prefix to use for querying all errors of the item. </param>
        /// <param name="resultPrefix"> Wildcard string prefix to use for querying all sub-tem results of the item. </param>
        /// <param name="lastStorageUpdatedOn"> Last time the storage was updated. </param>
        internal MigrateMySqlAzureDBForMySqlOfflineTaskOutputTableLevel(string id, string resultType, IDictionary<string, BinaryData> serializedAdditionalRawData, string objectName, DateTimeOffset? startedOn, DateTimeOffset? endedOn, DataMigrationState? state, string statusMessage, long? itemsCount, long? itemsCompletedCount, string errorPrefix, string resultPrefix, DateTimeOffset? lastStorageUpdatedOn) : base(id, resultType, serializedAdditionalRawData)
        {
            ObjectName = objectName;
            StartedOn = startedOn;
            EndedOn = endedOn;
            State = state;
            StatusMessage = statusMessage;
            ItemsCount = itemsCount;
            ItemsCompletedCount = itemsCompletedCount;
            ErrorPrefix = errorPrefix;
            ResultPrefix = resultPrefix;
            LastStorageUpdatedOn = lastStorageUpdatedOn;
            ResultType = resultType ?? "TableLevelOutput";
        }

        /// <summary> Name of the item. </summary>
        public string ObjectName { get; }
        /// <summary> Migration start time. </summary>
        public DateTimeOffset? StartedOn { get; }
        /// <summary> Migration end time. </summary>
        public DateTimeOffset? EndedOn { get; }
        /// <summary> Current state of migration. </summary>
        public DataMigrationState? State { get; }
        /// <summary> Status message. </summary>
        public string StatusMessage { get; }
        /// <summary> Number of items. </summary>
        public long? ItemsCount { get; }
        /// <summary> Number of successfully completed items. </summary>
        public long? ItemsCompletedCount { get; }
        /// <summary> Wildcard string prefix to use for querying all errors of the item. </summary>
        public string ErrorPrefix { get; }
        /// <summary> Wildcard string prefix to use for querying all sub-tem results of the item. </summary>
        public string ResultPrefix { get; }
        /// <summary> Last time the storage was updated. </summary>
        public DateTimeOffset? LastStorageUpdatedOn { get; }
    }
}
