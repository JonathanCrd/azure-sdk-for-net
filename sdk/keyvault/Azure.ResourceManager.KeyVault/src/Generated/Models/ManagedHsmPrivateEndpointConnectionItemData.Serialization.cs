// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.ResourceManager.Resources.Models;

namespace Azure.ResourceManager.KeyVault.Models
{
    public partial class ManagedHsmPrivateEndpointConnectionItemData : IUtf8JsonSerializable, IJsonModel<ManagedHsmPrivateEndpointConnectionItemData>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<ManagedHsmPrivateEndpointConnectionItemData>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<ManagedHsmPrivateEndpointConnectionItemData>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ManagedHsmPrivateEndpointConnectionItemData>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(ManagedHsmPrivateEndpointConnectionItemData)} does not support writing '{format}' format.");
            }

            if (Optional.IsDefined(Id))
            {
                writer.WritePropertyName("id"u8);
                writer.WriteStringValue(Id);
            }
            if (Optional.IsDefined(ETag))
            {
                writer.WritePropertyName("etag"u8);
                writer.WriteStringValue(ETag.Value.ToString());
            }
            writer.WritePropertyName("properties"u8);
            writer.WriteStartObject();
            if (Optional.IsDefined(PrivateEndpoint))
            {
                writer.WritePropertyName("privateEndpoint"u8);
                ((IJsonModel<SubResource>)PrivateEndpoint).Write(writer, options);
            }
            if (Optional.IsDefined(PrivateLinkServiceConnectionState))
            {
                writer.WritePropertyName("privateLinkServiceConnectionState"u8);
                writer.WriteObjectValue(PrivateLinkServiceConnectionState, options);
            }
            if (options.Format != "W" && Optional.IsDefined(ProvisioningState))
            {
                writer.WritePropertyName("provisioningState"u8);
                writer.WriteStringValue(ProvisioningState.Value.ToString());
            }
            writer.WriteEndObject();
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

        ManagedHsmPrivateEndpointConnectionItemData IJsonModel<ManagedHsmPrivateEndpointConnectionItemData>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ManagedHsmPrivateEndpointConnectionItemData>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(ManagedHsmPrivateEndpointConnectionItemData)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeManagedHsmPrivateEndpointConnectionItemData(document.RootElement, options);
        }

        internal static ManagedHsmPrivateEndpointConnectionItemData DeserializeManagedHsmPrivateEndpointConnectionItemData(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            ResourceIdentifier id = default;
            ETag? etag = default;
            SubResource privateEndpoint = default;
            ManagedHsmPrivateLinkServiceConnectionState privateLinkServiceConnectionState = default;
            ManagedHsmPrivateEndpointConnectionProvisioningState? provisioningState = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("id"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    id = new ResourceIdentifier(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("etag"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    etag = new ETag(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("properties"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        property.ThrowNonNullablePropertyIsNull();
                        continue;
                    }
                    foreach (var property0 in property.Value.EnumerateObject())
                    {
                        if (property0.NameEquals("privateEndpoint"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            privateEndpoint = ModelReaderWriter.Read<SubResource>(new BinaryData(Encoding.UTF8.GetBytes(property0.Value.GetRawText())), options, AzureResourceManagerKeyVaultContext.Default);
                            continue;
                        }
                        if (property0.NameEquals("privateLinkServiceConnectionState"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            privateLinkServiceConnectionState = ManagedHsmPrivateLinkServiceConnectionState.DeserializeManagedHsmPrivateLinkServiceConnectionState(property0.Value, options);
                            continue;
                        }
                        if (property0.NameEquals("provisioningState"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            provisioningState = new ManagedHsmPrivateEndpointConnectionProvisioningState(property0.Value.GetString());
                            continue;
                        }
                    }
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new ManagedHsmPrivateEndpointConnectionItemData(
                id,
                etag,
                privateEndpoint,
                privateLinkServiceConnectionState,
                provisioningState,
                serializedAdditionalRawData);
        }

        private BinaryData SerializeBicep(ModelReaderWriterOptions options)
        {
            StringBuilder builder = new StringBuilder();
            BicepModelReaderWriterOptions bicepOptions = options as BicepModelReaderWriterOptions;
            IDictionary<string, string> propertyOverrides = null;
            bool hasObjectOverride = bicepOptions != null && bicepOptions.PropertyOverrides.TryGetValue(this, out propertyOverrides);
            bool hasPropertyOverride = false;
            string propertyOverride = null;

            builder.AppendLine("{");

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(Id), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  id: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(Id))
                {
                    builder.Append("  id: ");
                    builder.AppendLine($"'{Id.ToString()}'");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(ETag), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  etag: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(ETag))
                {
                    builder.Append("  etag: ");
                    builder.AppendLine($"'{ETag.Value.ToString()}'");
                }
            }

            builder.Append("  properties:");
            builder.AppendLine(" {");
            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue("PrivateEndpointId", out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    privateEndpoint: ");
                builder.AppendLine("{");
                builder.AppendLine("      privateEndpoint: {");
                builder.Append("        id: ");
                builder.AppendLine(propertyOverride);
                builder.AppendLine("      }");
                builder.AppendLine("    }");
            }
            else
            {
                if (Optional.IsDefined(PrivateEndpoint))
                {
                    builder.Append("    privateEndpoint: ");
                    BicepSerializationHelpers.AppendChildObject(builder, PrivateEndpoint, options, 4, false, "    privateEndpoint: ");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(PrivateLinkServiceConnectionState), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    privateLinkServiceConnectionState: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(PrivateLinkServiceConnectionState))
                {
                    builder.Append("    privateLinkServiceConnectionState: ");
                    BicepSerializationHelpers.AppendChildObject(builder, PrivateLinkServiceConnectionState, options, 4, false, "    privateLinkServiceConnectionState: ");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(ProvisioningState), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    provisioningState: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(ProvisioningState))
                {
                    builder.Append("    provisioningState: ");
                    builder.AppendLine($"'{ProvisioningState.Value.ToString()}'");
                }
            }

            builder.AppendLine("  }");
            builder.AppendLine("}");
            return BinaryData.FromString(builder.ToString());
        }

        BinaryData IPersistableModel<ManagedHsmPrivateEndpointConnectionItemData>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ManagedHsmPrivateEndpointConnectionItemData>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerKeyVaultContext.Default);
                case "bicep":
                    return SerializeBicep(options);
                default:
                    throw new FormatException($"The model {nameof(ManagedHsmPrivateEndpointConnectionItemData)} does not support writing '{options.Format}' format.");
            }
        }

        ManagedHsmPrivateEndpointConnectionItemData IPersistableModel<ManagedHsmPrivateEndpointConnectionItemData>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ManagedHsmPrivateEndpointConnectionItemData>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeManagedHsmPrivateEndpointConnectionItemData(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(ManagedHsmPrivateEndpointConnectionItemData)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<ManagedHsmPrivateEndpointConnectionItemData>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
