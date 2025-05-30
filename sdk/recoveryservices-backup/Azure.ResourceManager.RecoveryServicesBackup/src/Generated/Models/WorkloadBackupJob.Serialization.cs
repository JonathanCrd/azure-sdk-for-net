// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.RecoveryServicesBackup.Models
{
    public partial class WorkloadBackupJob : IUtf8JsonSerializable, IJsonModel<WorkloadBackupJob>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<WorkloadBackupJob>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<WorkloadBackupJob>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected override void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<WorkloadBackupJob>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(WorkloadBackupJob)} does not support writing '{format}' format.");
            }

            base.JsonModelWriteCore(writer, options);
            if (Optional.IsDefined(WorkloadType))
            {
                writer.WritePropertyName("workloadType"u8);
                writer.WriteStringValue(WorkloadType);
            }
            if (Optional.IsDefined(Duration))
            {
                writer.WritePropertyName("duration"u8);
                writer.WriteStringValue(Duration.Value, "P");
            }
            if (Optional.IsCollectionDefined(ActionsInfo))
            {
                writer.WritePropertyName("actionsInfo"u8);
                writer.WriteStartArray();
                foreach (var item in ActionsInfo)
                {
                    writer.WriteStringValue(item.ToSerialString());
                }
                writer.WriteEndArray();
            }
            if (Optional.IsCollectionDefined(ErrorDetails))
            {
                writer.WritePropertyName("errorDetails"u8);
                writer.WriteStartArray();
                foreach (var item in ErrorDetails)
                {
                    writer.WriteObjectValue(item, options);
                }
                writer.WriteEndArray();
            }
            if (Optional.IsDefined(ExtendedInfo))
            {
                writer.WritePropertyName("extendedInfo"u8);
                writer.WriteObjectValue(ExtendedInfo, options);
            }
        }

        WorkloadBackupJob IJsonModel<WorkloadBackupJob>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<WorkloadBackupJob>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(WorkloadBackupJob)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeWorkloadBackupJob(document.RootElement, options);
        }

        internal static WorkloadBackupJob DeserializeWorkloadBackupJob(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string workloadType = default;
            TimeSpan? duration = default;
            IList<JobSupportedAction> actionsInfo = default;
            IList<WorkloadErrorInfo> errorDetails = default;
            WorkloadBackupJobExtendedInfo extendedInfo = default;
            string entityFriendlyName = default;
            BackupManagementType? backupManagementType = default;
            string operation = default;
            string status = default;
            DateTimeOffset? startTime = default;
            DateTimeOffset? endTime = default;
            string activityId = default;
            string jobType = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("workloadType"u8))
                {
                    workloadType = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("duration"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    duration = property.Value.GetTimeSpan("P");
                    continue;
                }
                if (property.NameEquals("actionsInfo"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    List<JobSupportedAction> array = new List<JobSupportedAction>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(item.GetString().ToJobSupportedAction());
                    }
                    actionsInfo = array;
                    continue;
                }
                if (property.NameEquals("errorDetails"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    List<WorkloadErrorInfo> array = new List<WorkloadErrorInfo>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(WorkloadErrorInfo.DeserializeWorkloadErrorInfo(item, options));
                    }
                    errorDetails = array;
                    continue;
                }
                if (property.NameEquals("extendedInfo"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    extendedInfo = WorkloadBackupJobExtendedInfo.DeserializeWorkloadBackupJobExtendedInfo(property.Value, options);
                    continue;
                }
                if (property.NameEquals("entityFriendlyName"u8))
                {
                    entityFriendlyName = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("backupManagementType"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    backupManagementType = new BackupManagementType(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("operation"u8))
                {
                    operation = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("status"u8))
                {
                    status = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("startTime"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    startTime = property.Value.GetDateTimeOffset("O");
                    continue;
                }
                if (property.NameEquals("endTime"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    endTime = property.Value.GetDateTimeOffset("O");
                    continue;
                }
                if (property.NameEquals("activityId"u8))
                {
                    activityId = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("jobType"u8))
                {
                    jobType = property.Value.GetString();
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new WorkloadBackupJob(
                entityFriendlyName,
                backupManagementType,
                operation,
                status,
                startTime,
                endTime,
                activityId,
                jobType,
                serializedAdditionalRawData,
                workloadType,
                duration,
                actionsInfo ?? new ChangeTrackingList<JobSupportedAction>(),
                errorDetails ?? new ChangeTrackingList<WorkloadErrorInfo>(),
                extendedInfo);
        }

        BinaryData IPersistableModel<WorkloadBackupJob>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<WorkloadBackupJob>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerRecoveryServicesBackupContext.Default);
                default:
                    throw new FormatException($"The model {nameof(WorkloadBackupJob)} does not support writing '{options.Format}' format.");
            }
        }

        WorkloadBackupJob IPersistableModel<WorkloadBackupJob>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<WorkloadBackupJob>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeWorkloadBackupJob(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(WorkloadBackupJob)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<WorkloadBackupJob>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
