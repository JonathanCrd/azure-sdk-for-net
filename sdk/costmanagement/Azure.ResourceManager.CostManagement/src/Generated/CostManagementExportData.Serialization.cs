// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.ResourceManager.CostManagement.Models;
using Azure.ResourceManager.Models;

namespace Azure.ResourceManager.CostManagement
{
    public partial class CostManagementExportData : IUtf8JsonSerializable, IJsonModel<CostManagementExportData>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<CostManagementExportData>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<CostManagementExportData>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected override void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<CostManagementExportData>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(CostManagementExportData)} does not support writing '{format}' format.");
            }

            base.JsonModelWriteCore(writer, options);
            if (Optional.IsDefined(ETag))
            {
                writer.WritePropertyName("eTag"u8);
                writer.WriteStringValue(ETag.Value.ToString());
            }
            writer.WritePropertyName("properties"u8);
            writer.WriteStartObject();
            if (Optional.IsDefined(Format))
            {
                writer.WritePropertyName("format"u8);
                writer.WriteStringValue(Format.Value.ToString());
            }
            if (Optional.IsDefined(DeliveryInfo))
            {
                writer.WritePropertyName("deliveryInfo"u8);
                writer.WriteObjectValue(DeliveryInfo, options);
            }
            if (Optional.IsDefined(Definition))
            {
                writer.WritePropertyName("definition"u8);
                writer.WriteObjectValue(Definition, options);
            }
            if (Optional.IsDefined(RunHistory))
            {
                writer.WritePropertyName("runHistory"u8);
                writer.WriteObjectValue(RunHistory, options);
            }
            if (Optional.IsDefined(PartitionData))
            {
                writer.WritePropertyName("partitionData"u8);
                writer.WriteBooleanValue(PartitionData.Value);
            }
            if (options.Format != "W" && Optional.IsDefined(NextRunTimeEstimate))
            {
                writer.WritePropertyName("nextRunTimeEstimate"u8);
                writer.WriteStringValue(NextRunTimeEstimate.Value, "O");
            }
            if (Optional.IsDefined(Schedule))
            {
                writer.WritePropertyName("schedule"u8);
                writer.WriteObjectValue(Schedule, options);
            }
            writer.WriteEndObject();
        }

        CostManagementExportData IJsonModel<CostManagementExportData>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<CostManagementExportData>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(CostManagementExportData)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeCostManagementExportData(document.RootElement, options);
        }

        internal static CostManagementExportData DeserializeCostManagementExportData(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            ETag? eTag = default;
            ResourceIdentifier id = default;
            string name = default;
            ResourceType type = default;
            SystemData systemData = default;
            ExportFormatType? format = default;
            ExportDeliveryInfo deliveryInfo = default;
            ExportDefinition definition = default;
            ExportExecutionListResult runHistory = default;
            bool? partitionData = default;
            DateTimeOffset? nextRunTimeEstimate = default;
            ExportSchedule schedule = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("eTag"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    eTag = new ETag(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("id"u8))
                {
                    ReadId(property, ref id);
                    continue;
                }
                if (property.NameEquals("name"u8))
                {
                    name = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("type"u8))
                {
                    type = new ResourceType(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("systemData"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    systemData = ModelReaderWriter.Read<SystemData>(new BinaryData(Encoding.UTF8.GetBytes(property.Value.GetRawText())), ModelSerializationExtensions.WireOptions, AzureResourceManagerCostManagementContext.Default);
                    continue;
                }
                if (property.NameEquals("properties"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        property.ThrowNonNullablePropertyIsNull();
                        continue;
                    }
                    foreach (var property0 in property.Value.EnumerateObject())
                    {
                        if (property0.NameEquals("format"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            format = new ExportFormatType(property0.Value.GetString());
                            continue;
                        }
                        if (property0.NameEquals("deliveryInfo"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            deliveryInfo = ExportDeliveryInfo.DeserializeExportDeliveryInfo(property0.Value, options);
                            continue;
                        }
                        if (property0.NameEquals("definition"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            definition = ExportDefinition.DeserializeExportDefinition(property0.Value, options);
                            continue;
                        }
                        if (property0.NameEquals("runHistory"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            runHistory = ExportExecutionListResult.DeserializeExportExecutionListResult(property0.Value, options);
                            continue;
                        }
                        if (property0.NameEquals("partitionData"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            partitionData = property0.Value.GetBoolean();
                            continue;
                        }
                        if (property0.NameEquals("nextRunTimeEstimate"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            nextRunTimeEstimate = property0.Value.GetDateTimeOffset("O");
                            continue;
                        }
                        if (property0.NameEquals("schedule"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            schedule = ExportSchedule.DeserializeExportSchedule(property0.Value, options);
                            continue;
                        }
                    }
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new CostManagementExportData(
                id,
                name,
                type,
                systemData,
                format,
                deliveryInfo,
                definition,
                runHistory,
                partitionData,
                nextRunTimeEstimate,
                schedule,
                eTag,
                serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<CostManagementExportData>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<CostManagementExportData>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerCostManagementContext.Default);
                default:
                    throw new FormatException($"The model {nameof(CostManagementExportData)} does not support writing '{options.Format}' format.");
            }
        }

        CostManagementExportData IPersistableModel<CostManagementExportData>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<CostManagementExportData>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeCostManagementExportData(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(CostManagementExportData)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<CostManagementExportData>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
