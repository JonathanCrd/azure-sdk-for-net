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
    public partial class P2SVpnConnectionHealth : IUtf8JsonSerializable, IJsonModel<P2SVpnConnectionHealth>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<P2SVpnConnectionHealth>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<P2SVpnConnectionHealth>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<P2SVpnConnectionHealth>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(P2SVpnConnectionHealth)} does not support writing '{format}' format.");
            }

            if (Optional.IsDefined(SasUri))
            {
                writer.WritePropertyName("sasUrl"u8);
                writer.WriteStringValue(SasUri.AbsoluteUri);
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

        P2SVpnConnectionHealth IJsonModel<P2SVpnConnectionHealth>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<P2SVpnConnectionHealth>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(P2SVpnConnectionHealth)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeP2SVpnConnectionHealth(document.RootElement, options);
        }

        internal static P2SVpnConnectionHealth DeserializeP2SVpnConnectionHealth(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            Uri sasUrl = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("sasUrl"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    sasUrl = new Uri(property.Value.GetString());
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new P2SVpnConnectionHealth(sasUrl, serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<P2SVpnConnectionHealth>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<P2SVpnConnectionHealth>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerNetworkContext.Default);
                default:
                    throw new FormatException($"The model {nameof(P2SVpnConnectionHealth)} does not support writing '{options.Format}' format.");
            }
        }

        P2SVpnConnectionHealth IPersistableModel<P2SVpnConnectionHealth>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<P2SVpnConnectionHealth>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeP2SVpnConnectionHealth(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(P2SVpnConnectionHealth)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<P2SVpnConnectionHealth>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
