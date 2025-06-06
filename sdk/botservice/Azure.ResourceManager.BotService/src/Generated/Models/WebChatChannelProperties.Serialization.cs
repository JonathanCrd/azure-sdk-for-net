// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.BotService.Models
{
    public partial class WebChatChannelProperties : IUtf8JsonSerializable, IJsonModel<WebChatChannelProperties>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<WebChatChannelProperties>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<WebChatChannelProperties>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<WebChatChannelProperties>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(WebChatChannelProperties)} does not support writing '{format}' format.");
            }

            if (options.Format != "W" && Optional.IsDefined(WebChatEmbedCode))
            {
                writer.WritePropertyName("webChatEmbedCode"u8);
                writer.WriteStringValue(WebChatEmbedCode);
            }
            if (Optional.IsCollectionDefined(Sites))
            {
                writer.WritePropertyName("sites"u8);
                writer.WriteStartArray();
                foreach (var item in Sites)
                {
                    writer.WriteObjectValue(item, options);
                }
                writer.WriteEndArray();
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

        WebChatChannelProperties IJsonModel<WebChatChannelProperties>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<WebChatChannelProperties>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(WebChatChannelProperties)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeWebChatChannelProperties(document.RootElement, options);
        }

        internal static WebChatChannelProperties DeserializeWebChatChannelProperties(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string webChatEmbedCode = default;
            IList<WebChatSite> sites = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("webChatEmbedCode"u8))
                {
                    webChatEmbedCode = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("sites"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    List<WebChatSite> array = new List<WebChatSite>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(WebChatSite.DeserializeWebChatSite(item, options));
                    }
                    sites = array;
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new WebChatChannelProperties(webChatEmbedCode, sites ?? new ChangeTrackingList<WebChatSite>(), serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<WebChatChannelProperties>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<WebChatChannelProperties>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerBotServiceContext.Default);
                default:
                    throw new FormatException($"The model {nameof(WebChatChannelProperties)} does not support writing '{options.Format}' format.");
            }
        }

        WebChatChannelProperties IPersistableModel<WebChatChannelProperties>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<WebChatChannelProperties>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeWebChatChannelProperties(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(WebChatChannelProperties)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<WebChatChannelProperties>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
