// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.IotOperations.Models
{
    public partial class BrokerAuthenticatorMethods : IUtf8JsonSerializable, IJsonModel<BrokerAuthenticatorMethods>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<BrokerAuthenticatorMethods>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<BrokerAuthenticatorMethods>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<BrokerAuthenticatorMethods>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(BrokerAuthenticatorMethods)} does not support writing '{format}' format.");
            }

            writer.WritePropertyName("method"u8);
            writer.WriteStringValue(Method.ToString());
            if (Optional.IsDefined(CustomSettings))
            {
                writer.WritePropertyName("customSettings"u8);
                writer.WriteObjectValue(CustomSettings, options);
            }
            if (Optional.IsDefined(ServiceAccountTokenSettings))
            {
                writer.WritePropertyName("serviceAccountTokenSettings"u8);
                writer.WriteObjectValue(ServiceAccountTokenSettings, options);
            }
            if (Optional.IsDefined(X509Settings))
            {
                writer.WritePropertyName("x509Settings"u8);
                writer.WriteObjectValue(X509Settings, options);
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

        BrokerAuthenticatorMethods IJsonModel<BrokerAuthenticatorMethods>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<BrokerAuthenticatorMethods>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(BrokerAuthenticatorMethods)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeBrokerAuthenticatorMethods(document.RootElement, options);
        }

        internal static BrokerAuthenticatorMethods DeserializeBrokerAuthenticatorMethods(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            BrokerAuthenticationMethod method = default;
            BrokerAuthenticatorMethodCustom customSettings = default;
            BrokerAuthenticatorMethodSat serviceAccountTokenSettings = default;
            BrokerAuthenticatorMethodX509 x509Settings = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("method"u8))
                {
                    method = new BrokerAuthenticationMethod(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("customSettings"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    customSettings = BrokerAuthenticatorMethodCustom.DeserializeBrokerAuthenticatorMethodCustom(property.Value, options);
                    continue;
                }
                if (property.NameEquals("serviceAccountTokenSettings"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    serviceAccountTokenSettings = BrokerAuthenticatorMethodSat.DeserializeBrokerAuthenticatorMethodSat(property.Value, options);
                    continue;
                }
                if (property.NameEquals("x509Settings"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    x509Settings = BrokerAuthenticatorMethodX509.DeserializeBrokerAuthenticatorMethodX509(property.Value, options);
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new BrokerAuthenticatorMethods(method, customSettings, serviceAccountTokenSettings, x509Settings, serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<BrokerAuthenticatorMethods>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<BrokerAuthenticatorMethods>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerIotOperationsContext.Default);
                default:
                    throw new FormatException($"The model {nameof(BrokerAuthenticatorMethods)} does not support writing '{options.Format}' format.");
            }
        }

        BrokerAuthenticatorMethods IPersistableModel<BrokerAuthenticatorMethods>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<BrokerAuthenticatorMethods>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeBrokerAuthenticatorMethods(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(BrokerAuthenticatorMethods)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<BrokerAuthenticatorMethods>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
