// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.DataMigration.Models
{
    public partial class DeletedIntegrationRuntimeNodeResult : IUtf8JsonSerializable, IJsonModel<DeletedIntegrationRuntimeNodeResult>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<DeletedIntegrationRuntimeNodeResult>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<DeletedIntegrationRuntimeNodeResult>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<DeletedIntegrationRuntimeNodeResult>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(DeletedIntegrationRuntimeNodeResult)} does not support writing '{format}' format.");
            }

            if (Optional.IsDefined(NodeName))
            {
                writer.WritePropertyName("nodeName"u8);
                writer.WriteStringValue(NodeName);
            }
            if (Optional.IsDefined(IntegrationRuntimeName))
            {
                writer.WritePropertyName("integrationRuntimeName"u8);
                writer.WriteStringValue(IntegrationRuntimeName);
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

        DeletedIntegrationRuntimeNodeResult IJsonModel<DeletedIntegrationRuntimeNodeResult>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<DeletedIntegrationRuntimeNodeResult>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(DeletedIntegrationRuntimeNodeResult)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeDeletedIntegrationRuntimeNodeResult(document.RootElement, options);
        }

        internal static DeletedIntegrationRuntimeNodeResult DeserializeDeletedIntegrationRuntimeNodeResult(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string nodeName = default;
            string integrationRuntimeName = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("nodeName"u8))
                {
                    nodeName = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("integrationRuntimeName"u8))
                {
                    integrationRuntimeName = property.Value.GetString();
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new DeletedIntegrationRuntimeNodeResult(nodeName, integrationRuntimeName, serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<DeletedIntegrationRuntimeNodeResult>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<DeletedIntegrationRuntimeNodeResult>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerDataMigrationContext.Default);
                default:
                    throw new FormatException($"The model {nameof(DeletedIntegrationRuntimeNodeResult)} does not support writing '{options.Format}' format.");
            }
        }

        DeletedIntegrationRuntimeNodeResult IPersistableModel<DeletedIntegrationRuntimeNodeResult>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<DeletedIntegrationRuntimeNodeResult>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeDeletedIntegrationRuntimeNodeResult(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(DeletedIntegrationRuntimeNodeResult)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<DeletedIntegrationRuntimeNodeResult>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
