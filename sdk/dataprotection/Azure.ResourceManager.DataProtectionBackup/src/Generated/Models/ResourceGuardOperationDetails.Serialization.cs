// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.DataProtectionBackup.Models
{
    public partial class ResourceGuardOperationDetails : IUtf8JsonSerializable, IJsonModel<ResourceGuardOperationDetails>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<ResourceGuardOperationDetails>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<ResourceGuardOperationDetails>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ResourceGuardOperationDetails>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(ResourceGuardOperationDetails)} does not support writing '{format}' format.");
            }

            if (options.Format != "W" && Optional.IsDefined(VaultCriticalOperation))
            {
                writer.WritePropertyName("vaultCriticalOperation"u8);
                writer.WriteStringValue(VaultCriticalOperation);
            }
            if (options.Format != "W" && Optional.IsDefined(RequestResourceType))
            {
                writer.WritePropertyName("requestResourceType"u8);
                writer.WriteStringValue(RequestResourceType.Value);
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

        ResourceGuardOperationDetails IJsonModel<ResourceGuardOperationDetails>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ResourceGuardOperationDetails>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(ResourceGuardOperationDetails)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeResourceGuardOperationDetails(document.RootElement, options);
        }

        internal static ResourceGuardOperationDetails DeserializeResourceGuardOperationDetails(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string vaultCriticalOperation = default;
            ResourceType? requestResourceType = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("vaultCriticalOperation"u8))
                {
                    vaultCriticalOperation = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("requestResourceType"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    requestResourceType = new ResourceType(property.Value.GetString());
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new ResourceGuardOperationDetails(vaultCriticalOperation, requestResourceType, serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<ResourceGuardOperationDetails>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ResourceGuardOperationDetails>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerDataProtectionBackupContext.Default);
                default:
                    throw new FormatException($"The model {nameof(ResourceGuardOperationDetails)} does not support writing '{options.Format}' format.");
            }
        }

        ResourceGuardOperationDetails IPersistableModel<ResourceGuardOperationDetails>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ResourceGuardOperationDetails>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeResourceGuardOperationDetails(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(ResourceGuardOperationDetails)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<ResourceGuardOperationDetails>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
