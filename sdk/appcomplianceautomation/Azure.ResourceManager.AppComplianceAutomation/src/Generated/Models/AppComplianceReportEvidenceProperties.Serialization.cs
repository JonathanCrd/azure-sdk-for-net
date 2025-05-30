// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.AppComplianceAutomation.Models
{
    public partial class AppComplianceReportEvidenceProperties : IUtf8JsonSerializable, IJsonModel<AppComplianceReportEvidenceProperties>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<AppComplianceReportEvidenceProperties>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<AppComplianceReportEvidenceProperties>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AppComplianceReportEvidenceProperties>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(AppComplianceReportEvidenceProperties)} does not support writing '{format}' format.");
            }

            if (Optional.IsDefined(EvidenceType))
            {
                writer.WritePropertyName("evidenceType"u8);
                writer.WriteStringValue(EvidenceType.Value.ToString());
            }
            writer.WritePropertyName("filePath"u8);
            writer.WriteStringValue(FilePath);
            if (Optional.IsDefined(ExtraData))
            {
                writer.WritePropertyName("extraData"u8);
                writer.WriteStringValue(ExtraData);
            }
            if (Optional.IsDefined(ControlId))
            {
                writer.WritePropertyName("controlId"u8);
                writer.WriteStringValue(ControlId);
            }
            if (Optional.IsDefined(ResponsibilityId))
            {
                writer.WritePropertyName("responsibilityId"u8);
                writer.WriteStringValue(ResponsibilityId);
            }
            if (options.Format != "W" && Optional.IsDefined(ProvisioningState))
            {
                writer.WritePropertyName("provisioningState"u8);
                writer.WriteStringValue(ProvisioningState.Value.ToString());
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

        AppComplianceReportEvidenceProperties IJsonModel<AppComplianceReportEvidenceProperties>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AppComplianceReportEvidenceProperties>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(AppComplianceReportEvidenceProperties)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeAppComplianceReportEvidenceProperties(document.RootElement, options);
        }

        internal static AppComplianceReportEvidenceProperties DeserializeAppComplianceReportEvidenceProperties(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            AppComplianceReportEvidenceType? evidenceType = default;
            string filePath = default;
            string extraData = default;
            string controlId = default;
            string responsibilityId = default;
            AppComplianceProvisioningState? provisioningState = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("evidenceType"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    evidenceType = new AppComplianceReportEvidenceType(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("filePath"u8))
                {
                    filePath = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("extraData"u8))
                {
                    extraData = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("controlId"u8))
                {
                    controlId = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("responsibilityId"u8))
                {
                    responsibilityId = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("provisioningState"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    provisioningState = new AppComplianceProvisioningState(property.Value.GetString());
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new AppComplianceReportEvidenceProperties(
                evidenceType,
                filePath,
                extraData,
                controlId,
                responsibilityId,
                provisioningState,
                serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<AppComplianceReportEvidenceProperties>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AppComplianceReportEvidenceProperties>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerAppComplianceAutomationContext.Default);
                default:
                    throw new FormatException($"The model {nameof(AppComplianceReportEvidenceProperties)} does not support writing '{options.Format}' format.");
            }
        }

        AppComplianceReportEvidenceProperties IPersistableModel<AppComplianceReportEvidenceProperties>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AppComplianceReportEvidenceProperties>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeAppComplianceReportEvidenceProperties(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(AppComplianceReportEvidenceProperties)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<AppComplianceReportEvidenceProperties>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
