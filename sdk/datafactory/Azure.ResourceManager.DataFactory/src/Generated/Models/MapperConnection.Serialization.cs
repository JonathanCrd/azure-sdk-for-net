// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Expressions.DataFactory;

namespace Azure.ResourceManager.DataFactory.Models
{
    public partial class MapperConnection : IUtf8JsonSerializable, IJsonModel<MapperConnection>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<MapperConnection>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<MapperConnection>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MapperConnection>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(MapperConnection)} does not support writing '{format}' format.");
            }

            if (Optional.IsDefined(LinkedService))
            {
                writer.WritePropertyName("linkedService"u8);
                JsonSerializer.Serialize(writer, LinkedService);
            }
            if (Optional.IsDefined(LinkedServiceType))
            {
                writer.WritePropertyName("linkedServiceType"u8);
                writer.WriteStringValue(LinkedServiceType);
            }
            writer.WritePropertyName("type"u8);
            writer.WriteStringValue(ConnectionType.ToString());
            if (Optional.IsDefined(IsInlineDataset))
            {
                writer.WritePropertyName("isInlineDataset"u8);
                writer.WriteBooleanValue(IsInlineDataset.Value);
            }
            if (Optional.IsCollectionDefined(CommonDslConnectorProperties))
            {
                writer.WritePropertyName("commonDslConnectorProperties"u8);
                writer.WriteStartArray();
                foreach (var item in CommonDslConnectorProperties)
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

        MapperConnection IJsonModel<MapperConnection>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MapperConnection>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(MapperConnection)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeMapperConnection(document.RootElement, options);
        }

        internal static MapperConnection DeserializeMapperConnection(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            DataFactoryLinkedServiceReference linkedService = default;
            string linkedServiceType = default;
            MapperConnectionType type = default;
            bool? isInlineDataset = default;
            IList<MapperDslConnectorProperties> commonDslConnectorProperties = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("linkedService"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    linkedService = JsonSerializer.Deserialize<DataFactoryLinkedServiceReference>(property.Value.GetRawText());
                    continue;
                }
                if (property.NameEquals("linkedServiceType"u8))
                {
                    linkedServiceType = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("type"u8))
                {
                    type = new MapperConnectionType(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("isInlineDataset"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    isInlineDataset = property.Value.GetBoolean();
                    continue;
                }
                if (property.NameEquals("commonDslConnectorProperties"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    List<MapperDslConnectorProperties> array = new List<MapperDslConnectorProperties>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(MapperDslConnectorProperties.DeserializeMapperDslConnectorProperties(item, options));
                    }
                    commonDslConnectorProperties = array;
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new MapperConnection(
                linkedService,
                linkedServiceType,
                type,
                isInlineDataset,
                commonDslConnectorProperties ?? new ChangeTrackingList<MapperDslConnectorProperties>(),
                serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<MapperConnection>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MapperConnection>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerDataFactoryContext.Default);
                default:
                    throw new FormatException($"The model {nameof(MapperConnection)} does not support writing '{options.Format}' format.");
            }
        }

        MapperConnection IPersistableModel<MapperConnection>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MapperConnection>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeMapperConnection(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(MapperConnection)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<MapperConnection>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
