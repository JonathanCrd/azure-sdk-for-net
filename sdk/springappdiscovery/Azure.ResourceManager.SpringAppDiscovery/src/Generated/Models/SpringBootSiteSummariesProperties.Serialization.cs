// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.SpringAppDiscovery.Models
{
    public partial class SpringBootSiteSummariesProperties : IUtf8JsonSerializable, IJsonModel<SpringBootSiteSummariesProperties>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<SpringBootSiteSummariesProperties>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<SpringBootSiteSummariesProperties>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<SpringBootSiteSummariesProperties>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(SpringBootSiteSummariesProperties)} does not support writing '{format}' format.");
            }

            if (Optional.IsDefined(DiscoveredServers))
            {
                writer.WritePropertyName("discoveredServers"u8);
                writer.WriteNumberValue(DiscoveredServers.Value);
            }
            if (Optional.IsDefined(DiscoveredApps))
            {
                writer.WritePropertyName("discoveredApps"u8);
                writer.WriteNumberValue(DiscoveredApps.Value);
            }
            if (Optional.IsCollectionDefined(Errors))
            {
                writer.WritePropertyName("errors"u8);
                writer.WriteStartArray();
                foreach (var item in Errors)
                {
                    writer.WriteObjectValue(item, options);
                }
                writer.WriteEndArray();
            }
            if (Optional.IsDefined(ProvisioningState))
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

        SpringBootSiteSummariesProperties IJsonModel<SpringBootSiteSummariesProperties>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<SpringBootSiteSummariesProperties>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(SpringBootSiteSummariesProperties)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeSpringBootSiteSummariesProperties(document.RootElement, options);
        }

        internal static SpringBootSiteSummariesProperties DeserializeSpringBootSiteSummariesProperties(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            long? discoveredServers = default;
            long? discoveredApps = default;
            IList<SpringBootSiteError> errors = default;
            SpringAppDiscoveryProvisioningState? provisioningState = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("discoveredServers"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    discoveredServers = property.Value.GetInt64();
                    continue;
                }
                if (property.NameEquals("discoveredApps"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    discoveredApps = property.Value.GetInt64();
                    continue;
                }
                if (property.NameEquals("errors"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    List<SpringBootSiteError> array = new List<SpringBootSiteError>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(SpringBootSiteError.DeserializeSpringBootSiteError(item, options));
                    }
                    errors = array;
                    continue;
                }
                if (property.NameEquals("provisioningState"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    provisioningState = new SpringAppDiscoveryProvisioningState(property.Value.GetString());
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new SpringBootSiteSummariesProperties(discoveredServers, discoveredApps, errors ?? new ChangeTrackingList<SpringBootSiteError>(), provisioningState, serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<SpringBootSiteSummariesProperties>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<SpringBootSiteSummariesProperties>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerSpringAppDiscoveryContext.Default);
                default:
                    throw new FormatException($"The model {nameof(SpringBootSiteSummariesProperties)} does not support writing '{options.Format}' format.");
            }
        }

        SpringBootSiteSummariesProperties IPersistableModel<SpringBootSiteSummariesProperties>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<SpringBootSiteSummariesProperties>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeSpringBootSiteSummariesProperties(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(SpringBootSiteSummariesProperties)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<SpringBootSiteSummariesProperties>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
