// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.RecoveryServicesSiteRecovery.Models
{
    public partial class InMageProtectedDiskDetails : IUtf8JsonSerializable, IJsonModel<InMageProtectedDiskDetails>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<InMageProtectedDiskDetails>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<InMageProtectedDiskDetails>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<InMageProtectedDiskDetails>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(InMageProtectedDiskDetails)} does not support writing '{format}' format.");
            }

            if (Optional.IsDefined(DiskId))
            {
                writer.WritePropertyName("diskId"u8);
                writer.WriteStringValue(DiskId);
            }
            if (Optional.IsDefined(DiskName))
            {
                writer.WritePropertyName("diskName"u8);
                writer.WriteStringValue(DiskName);
            }
            if (Optional.IsDefined(ProtectionStage))
            {
                writer.WritePropertyName("protectionStage"u8);
                writer.WriteStringValue(ProtectionStage);
            }
            if (Optional.IsDefined(HealthErrorCode))
            {
                writer.WritePropertyName("healthErrorCode"u8);
                writer.WriteStringValue(HealthErrorCode);
            }
            if (Optional.IsDefined(RpoInSeconds))
            {
                writer.WritePropertyName("rpoInSeconds"u8);
                writer.WriteNumberValue(RpoInSeconds.Value);
            }
            if (Optional.IsDefined(ResyncRequired))
            {
                writer.WritePropertyName("resyncRequired"u8);
                writer.WriteStringValue(ResyncRequired);
            }
            if (Optional.IsDefined(ResyncProgressPercentage))
            {
                writer.WritePropertyName("resyncProgressPercentage"u8);
                writer.WriteNumberValue(ResyncProgressPercentage.Value);
            }
            if (Optional.IsDefined(ResyncDurationInSeconds))
            {
                writer.WritePropertyName("resyncDurationInSeconds"u8);
                writer.WriteNumberValue(ResyncDurationInSeconds.Value);
            }
            if (Optional.IsDefined(DiskCapacityInBytes))
            {
                writer.WritePropertyName("diskCapacityInBytes"u8);
                writer.WriteNumberValue(DiskCapacityInBytes.Value);
            }
            if (Optional.IsDefined(FileSystemCapacityInBytes))
            {
                writer.WritePropertyName("fileSystemCapacityInBytes"u8);
                writer.WriteNumberValue(FileSystemCapacityInBytes.Value);
            }
            if (Optional.IsDefined(SourceDataInMB))
            {
                writer.WritePropertyName("sourceDataInMB"u8);
                writer.WriteNumberValue(SourceDataInMB.Value);
            }
            if (Optional.IsDefined(PSDataInMB))
            {
                writer.WritePropertyName("psDataInMB"u8);
                writer.WriteNumberValue(PSDataInMB.Value);
            }
            if (Optional.IsDefined(TargetDataInMB))
            {
                writer.WritePropertyName("targetDataInMB"u8);
                writer.WriteNumberValue(TargetDataInMB.Value);
            }
            if (Optional.IsDefined(DiskResized))
            {
                writer.WritePropertyName("diskResized"u8);
                writer.WriteStringValue(DiskResized);
            }
            if (Optional.IsDefined(LastRpoCalculatedOn))
            {
                writer.WritePropertyName("lastRpoCalculatedTime"u8);
                writer.WriteStringValue(LastRpoCalculatedOn.Value, "O");
            }
            if (Optional.IsDefined(ResyncProcessedBytes))
            {
                writer.WritePropertyName("resyncProcessedBytes"u8);
                writer.WriteNumberValue(ResyncProcessedBytes.Value);
            }
            if (Optional.IsDefined(ResyncTotalTransferredBytes))
            {
                writer.WritePropertyName("resyncTotalTransferredBytes"u8);
                writer.WriteNumberValue(ResyncTotalTransferredBytes.Value);
            }
            if (Optional.IsDefined(ResyncLast15MinutesTransferredBytes))
            {
                writer.WritePropertyName("resyncLast15MinutesTransferredBytes"u8);
                writer.WriteNumberValue(ResyncLast15MinutesTransferredBytes.Value);
            }
            if (Optional.IsDefined(ResyncLastDataTransferTimeUTC))
            {
                writer.WritePropertyName("resyncLastDataTransferTimeUTC"u8);
                writer.WriteStringValue(ResyncLastDataTransferTimeUTC.Value, "O");
            }
            if (Optional.IsDefined(ResyncStartOn))
            {
                writer.WritePropertyName("resyncStartTime"u8);
                writer.WriteStringValue(ResyncStartOn.Value, "O");
            }
            if (Optional.IsDefined(ProgressHealth))
            {
                writer.WritePropertyName("progressHealth"u8);
                writer.WriteStringValue(ProgressHealth);
            }
            if (Optional.IsDefined(ProgressStatus))
            {
                writer.WritePropertyName("progressStatus"u8);
                writer.WriteStringValue(ProgressStatus);
            }
            if (options.Format != "W" && _serializedAdditionalRawData != null)
            {
                foreach (var item in _serializedAdditionalRawData)
                {
                    writer.WritePropertyName(item.Key);
#if NET6_0_OR_GREATER
				writer.WriteRawValue(item.Value);
#else
                    using (JsonDocument document = JsonDocument.Parse(item.Value, ModelSerializationExtensions.JsonDocumentOptions))
                    {
                        JsonSerializer.Serialize(writer, document.RootElement);
                    }
#endif
                }
            }
        }

        InMageProtectedDiskDetails IJsonModel<InMageProtectedDiskDetails>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<InMageProtectedDiskDetails>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(InMageProtectedDiskDetails)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeInMageProtectedDiskDetails(document.RootElement, options);
        }

        internal static InMageProtectedDiskDetails DeserializeInMageProtectedDiskDetails(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string diskId = default;
            string diskName = default;
            string protectionStage = default;
            string healthErrorCode = default;
            long? rpoInSeconds = default;
            string resyncRequired = default;
            int? resyncProgressPercentage = default;
            long? resyncDurationInSeconds = default;
            long? diskCapacityInBytes = default;
            long? fileSystemCapacityInBytes = default;
            double? sourceDataInMB = default;
            double? psDataInMB = default;
            double? targetDataInMB = default;
            string diskResized = default;
            DateTimeOffset? lastRpoCalculatedTime = default;
            long? resyncProcessedBytes = default;
            long? resyncTotalTransferredBytes = default;
            long? resyncLast15MinutesTransferredBytes = default;
            DateTimeOffset? resyncLastDataTransferTimeUTC = default;
            DateTimeOffset? resyncStartTime = default;
            string progressHealth = default;
            string progressStatus = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("diskId"u8))
                {
                    diskId = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("diskName"u8))
                {
                    diskName = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("protectionStage"u8))
                {
                    protectionStage = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("healthErrorCode"u8))
                {
                    healthErrorCode = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("rpoInSeconds"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    rpoInSeconds = property.Value.GetInt64();
                    continue;
                }
                if (property.NameEquals("resyncRequired"u8))
                {
                    resyncRequired = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("resyncProgressPercentage"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    resyncProgressPercentage = property.Value.GetInt32();
                    continue;
                }
                if (property.NameEquals("resyncDurationInSeconds"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    resyncDurationInSeconds = property.Value.GetInt64();
                    continue;
                }
                if (property.NameEquals("diskCapacityInBytes"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    diskCapacityInBytes = property.Value.GetInt64();
                    continue;
                }
                if (property.NameEquals("fileSystemCapacityInBytes"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    fileSystemCapacityInBytes = property.Value.GetInt64();
                    continue;
                }
                if (property.NameEquals("sourceDataInMB"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    sourceDataInMB = property.Value.GetDouble();
                    continue;
                }
                if (property.NameEquals("psDataInMB"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    psDataInMB = property.Value.GetDouble();
                    continue;
                }
                if (property.NameEquals("targetDataInMB"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    targetDataInMB = property.Value.GetDouble();
                    continue;
                }
                if (property.NameEquals("diskResized"u8))
                {
                    diskResized = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("lastRpoCalculatedTime"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    lastRpoCalculatedTime = property.Value.GetDateTimeOffset("O");
                    continue;
                }
                if (property.NameEquals("resyncProcessedBytes"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    resyncProcessedBytes = property.Value.GetInt64();
                    continue;
                }
                if (property.NameEquals("resyncTotalTransferredBytes"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    resyncTotalTransferredBytes = property.Value.GetInt64();
                    continue;
                }
                if (property.NameEquals("resyncLast15MinutesTransferredBytes"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    resyncLast15MinutesTransferredBytes = property.Value.GetInt64();
                    continue;
                }
                if (property.NameEquals("resyncLastDataTransferTimeUTC"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    resyncLastDataTransferTimeUTC = property.Value.GetDateTimeOffset("O");
                    continue;
                }
                if (property.NameEquals("resyncStartTime"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    resyncStartTime = property.Value.GetDateTimeOffset("O");
                    continue;
                }
                if (property.NameEquals("progressHealth"u8))
                {
                    progressHealth = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("progressStatus"u8))
                {
                    progressStatus = property.Value.GetString();
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new InMageProtectedDiskDetails(
                diskId,
                diskName,
                protectionStage,
                healthErrorCode,
                rpoInSeconds,
                resyncRequired,
                resyncProgressPercentage,
                resyncDurationInSeconds,
                diskCapacityInBytes,
                fileSystemCapacityInBytes,
                sourceDataInMB,
                psDataInMB,
                targetDataInMB,
                diskResized,
                lastRpoCalculatedTime,
                resyncProcessedBytes,
                resyncTotalTransferredBytes,
                resyncLast15MinutesTransferredBytes,
                resyncLastDataTransferTimeUTC,
                resyncStartTime,
                progressHealth,
                progressStatus,
                serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<InMageProtectedDiskDetails>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<InMageProtectedDiskDetails>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerRecoveryServicesSiteRecoveryContext.Default);
                default:
                    throw new FormatException($"The model {nameof(InMageProtectedDiskDetails)} does not support writing '{options.Format}' format.");
            }
        }

        InMageProtectedDiskDetails IPersistableModel<InMageProtectedDiskDetails>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<InMageProtectedDiskDetails>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeInMageProtectedDiskDetails(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(InMageProtectedDiskDetails)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<InMageProtectedDiskDetails>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
