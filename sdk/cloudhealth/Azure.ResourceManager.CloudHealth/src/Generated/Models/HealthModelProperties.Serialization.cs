// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.CloudHealth.Models
{
    public partial class HealthModelProperties : IUtf8JsonSerializable, IJsonModel<HealthModelProperties>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<HealthModelProperties>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<HealthModelProperties>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<HealthModelProperties>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(HealthModelProperties)} does not support writing '{format}' format.");
            }

            if (options.Format != "W" && Optional.IsDefined(DataplaneEndpoint))
            {
                writer.WritePropertyName("dataplaneEndpoint"u8);
                writer.WriteStringValue(DataplaneEndpoint);
            }
            if (options.Format != "W" && Optional.IsDefined(ProvisioningState))
            {
                writer.WritePropertyName("provisioningState"u8);
                writer.WriteStringValue(ProvisioningState.Value.ToString());
            }
            if (Optional.IsDefined(Discovery))
            {
                writer.WritePropertyName("discovery"u8);
                writer.WriteObjectValue(Discovery, options);
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

        HealthModelProperties IJsonModel<HealthModelProperties>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<HealthModelProperties>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(HealthModelProperties)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeHealthModelProperties(document.RootElement, options);
        }

        internal static HealthModelProperties DeserializeHealthModelProperties(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string dataplaneEndpoint = default;
            HealthModelProvisioningState? provisioningState = default;
            ModelDiscoverySettings discovery = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("dataplaneEndpoint"u8))
                {
                    dataplaneEndpoint = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("provisioningState"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    provisioningState = new HealthModelProvisioningState(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("discovery"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    discovery = ModelDiscoverySettings.DeserializeModelDiscoverySettings(property.Value, options);
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new HealthModelProperties(dataplaneEndpoint, provisioningState, discovery, serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<HealthModelProperties>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<HealthModelProperties>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerCloudHealthContext.Default);
                default:
                    throw new FormatException($"The model {nameof(HealthModelProperties)} does not support writing '{options.Format}' format.");
            }
        }

        HealthModelProperties IPersistableModel<HealthModelProperties>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<HealthModelProperties>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeHealthModelProperties(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(HealthModelProperties)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<HealthModelProperties>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
