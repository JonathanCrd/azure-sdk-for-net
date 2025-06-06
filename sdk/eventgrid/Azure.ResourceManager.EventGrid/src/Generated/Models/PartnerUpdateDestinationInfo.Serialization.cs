// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.EventGrid.Models
{
    [PersistableModelProxy(typeof(UnknownPartnerUpdateDestinationInfo))]
    public partial class PartnerUpdateDestinationInfo : IUtf8JsonSerializable, IJsonModel<PartnerUpdateDestinationInfo>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<PartnerUpdateDestinationInfo>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<PartnerUpdateDestinationInfo>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<PartnerUpdateDestinationInfo>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(PartnerUpdateDestinationInfo)} does not support writing '{format}' format.");
            }

            writer.WritePropertyName("endpointType"u8);
            writer.WriteStringValue(EndpointType.ToString());
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

        PartnerUpdateDestinationInfo IJsonModel<PartnerUpdateDestinationInfo>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<PartnerUpdateDestinationInfo>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(PartnerUpdateDestinationInfo)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializePartnerUpdateDestinationInfo(document.RootElement, options);
        }

        internal static PartnerUpdateDestinationInfo DeserializePartnerUpdateDestinationInfo(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            if (element.TryGetProperty("endpointType", out JsonElement discriminator))
            {
                switch (discriminator.GetString())
                {
                    case "WebHook": return WebhookUpdatePartnerDestinationInfo.DeserializeWebhookUpdatePartnerDestinationInfo(element, options);
                }
            }
            return UnknownPartnerUpdateDestinationInfo.DeserializeUnknownPartnerUpdateDestinationInfo(element, options);
        }

        BinaryData IPersistableModel<PartnerUpdateDestinationInfo>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<PartnerUpdateDestinationInfo>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerEventGridContext.Default);
                default:
                    throw new FormatException($"The model {nameof(PartnerUpdateDestinationInfo)} does not support writing '{options.Format}' format.");
            }
        }

        PartnerUpdateDestinationInfo IPersistableModel<PartnerUpdateDestinationInfo>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<PartnerUpdateDestinationInfo>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializePartnerUpdateDestinationInfo(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(PartnerUpdateDestinationInfo)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<PartnerUpdateDestinationInfo>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
