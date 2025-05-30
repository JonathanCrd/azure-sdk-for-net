// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.Network.Models
{
    public partial class VirtualNetworkGatewayMigrationContent : IUtf8JsonSerializable, IJsonModel<VirtualNetworkGatewayMigrationContent>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<VirtualNetworkGatewayMigrationContent>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<VirtualNetworkGatewayMigrationContent>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<VirtualNetworkGatewayMigrationContent>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(VirtualNetworkGatewayMigrationContent)} does not support writing '{format}' format.");
            }

            writer.WritePropertyName("migrationType"u8);
            writer.WriteStringValue(MigrationType.ToString());
            if (Optional.IsDefined(ResourceUri))
            {
                writer.WritePropertyName("resourceUrl"u8);
                writer.WriteStringValue(ResourceUri.AbsoluteUri);
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

        VirtualNetworkGatewayMigrationContent IJsonModel<VirtualNetworkGatewayMigrationContent>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<VirtualNetworkGatewayMigrationContent>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(VirtualNetworkGatewayMigrationContent)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeVirtualNetworkGatewayMigrationContent(document.RootElement, options);
        }

        internal static VirtualNetworkGatewayMigrationContent DeserializeVirtualNetworkGatewayMigrationContent(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            VirtualNetworkGatewayMigrationType migrationType = default;
            Uri resourceUrl = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("migrationType"u8))
                {
                    migrationType = new VirtualNetworkGatewayMigrationType(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("resourceUrl"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    resourceUrl = new Uri(property.Value.GetString());
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new VirtualNetworkGatewayMigrationContent(migrationType, resourceUrl, serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<VirtualNetworkGatewayMigrationContent>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<VirtualNetworkGatewayMigrationContent>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerNetworkContext.Default);
                default:
                    throw new FormatException($"The model {nameof(VirtualNetworkGatewayMigrationContent)} does not support writing '{options.Format}' format.");
            }
        }

        VirtualNetworkGatewayMigrationContent IPersistableModel<VirtualNetworkGatewayMigrationContent>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<VirtualNetworkGatewayMigrationContent>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeVirtualNetworkGatewayMigrationContent(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(VirtualNetworkGatewayMigrationContent)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<VirtualNetworkGatewayMigrationContent>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
