// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.Migration.Assessment.Models
{
    public partial class AssessmentManagedDiskSkuDto : IUtf8JsonSerializable, IJsonModel<AssessmentManagedDiskSkuDto>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<AssessmentManagedDiskSkuDto>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<AssessmentManagedDiskSkuDto>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AssessmentManagedDiskSkuDto>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(AssessmentManagedDiskSkuDto)} does not support writing '{format}' format.");
            }

            if (options.Format != "W" && Optional.IsDefined(DiskType))
            {
                writer.WritePropertyName("diskType"u8);
                writer.WriteStringValue(DiskType.Value.ToString());
            }
            if (options.Format != "W" && Optional.IsDefined(DiskSize))
            {
                writer.WritePropertyName("diskSize"u8);
                writer.WriteStringValue(DiskSize.Value.ToString());
            }
            if (options.Format != "W" && Optional.IsDefined(DiskRedundancy))
            {
                writer.WritePropertyName("diskRedundancy"u8);
                writer.WriteStringValue(DiskRedundancy.Value.ToString());
            }
            if (options.Format != "W" && Optional.IsDefined(StorageCost))
            {
                writer.WritePropertyName("storageCost"u8);
                writer.WriteNumberValue(StorageCost.Value);
            }
            if (options.Format != "W" && Optional.IsDefined(RecommendedSizeInGib))
            {
                writer.WritePropertyName("recommendedSizeInGib"u8);
                writer.WriteNumberValue(RecommendedSizeInGib.Value);
            }
            if (options.Format != "W" && Optional.IsDefined(RecommendedThroughputInMbps))
            {
                writer.WritePropertyName("recommendedThroughputInMbps"u8);
                writer.WriteNumberValue(RecommendedThroughputInMbps.Value);
            }
            if (options.Format != "W" && Optional.IsDefined(RecommendedIops))
            {
                writer.WritePropertyName("recommendedIops"u8);
                writer.WriteNumberValue(RecommendedIops.Value);
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

        AssessmentManagedDiskSkuDto IJsonModel<AssessmentManagedDiskSkuDto>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AssessmentManagedDiskSkuDto>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(AssessmentManagedDiskSkuDto)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeAssessmentManagedDiskSkuDto(document.RootElement, options);
        }

        internal static AssessmentManagedDiskSkuDto DeserializeAssessmentManagedDiskSkuDto(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            ManagedDiskSkuDtoDiskType? diskType = default;
            AssessmentDiskSize? diskSize = default;
            ManagedDiskSkuDtoDiskRedundancy? diskRedundancy = default;
            double? storageCost = default;
            double? recommendedSizeInGib = default;
            double? recommendedThroughputInMbps = default;
            double? recommendedIops = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("diskType"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    diskType = new ManagedDiskSkuDtoDiskType(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("diskSize"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    diskSize = new AssessmentDiskSize(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("diskRedundancy"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    diskRedundancy = new ManagedDiskSkuDtoDiskRedundancy(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("storageCost"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    storageCost = property.Value.GetDouble();
                    continue;
                }
                if (property.NameEquals("recommendedSizeInGib"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    recommendedSizeInGib = property.Value.GetDouble();
                    continue;
                }
                if (property.NameEquals("recommendedThroughputInMbps"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    recommendedThroughputInMbps = property.Value.GetDouble();
                    continue;
                }
                if (property.NameEquals("recommendedIops"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    recommendedIops = property.Value.GetDouble();
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new AssessmentManagedDiskSkuDto(
                diskType,
                diskSize,
                diskRedundancy,
                storageCost,
                recommendedSizeInGib,
                recommendedThroughputInMbps,
                recommendedIops,
                serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<AssessmentManagedDiskSkuDto>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AssessmentManagedDiskSkuDto>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerMigrationAssessmentContext.Default);
                default:
                    throw new FormatException($"The model {nameof(AssessmentManagedDiskSkuDto)} does not support writing '{options.Format}' format.");
            }
        }

        AssessmentManagedDiskSkuDto IPersistableModel<AssessmentManagedDiskSkuDto>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AssessmentManagedDiskSkuDto>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeAssessmentManagedDiskSkuDto(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(AssessmentManagedDiskSkuDto)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<AssessmentManagedDiskSkuDto>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
