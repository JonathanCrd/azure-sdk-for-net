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
using Azure.ResourceManager.Models;

namespace Azure.ResourceManager.NetApp.Models
{
    public partial class NetAppAccountPatch : IUtf8JsonSerializable, IJsonModel<NetAppAccountPatch>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<NetAppAccountPatch>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<NetAppAccountPatch>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected override void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<NetAppAccountPatch>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(NetAppAccountPatch)} does not support writing '{format}' format.");
            }

            base.JsonModelWriteCore(writer, options);
            if (Optional.IsDefined(Identity))
            {
                writer.WritePropertyName("identity"u8);
                ((IJsonModel<ManagedServiceIdentity>)Identity).Write(writer, ModelSerializationExtensions.WireV3Options);
            }
            writer.WritePropertyName("properties"u8);
            writer.WriteStartObject();
            if (options.Format != "W" && Optional.IsDefined(ProvisioningState))
            {
                writer.WritePropertyName("provisioningState"u8);
                writer.WriteStringValue(ProvisioningState);
            }
            if (Optional.IsCollectionDefined(ActiveDirectories))
            {
                writer.WritePropertyName("activeDirectories"u8);
                writer.WriteStartArray();
                foreach (var item in ActiveDirectories)
                {
                    writer.WriteObjectValue(item, options);
                }
                writer.WriteEndArray();
            }
            if (Optional.IsDefined(Encryption))
            {
                writer.WritePropertyName("encryption"u8);
                writer.WriteObjectValue(Encryption, options);
            }
            if (options.Format != "W" && Optional.IsDefined(DisableShowmount))
            {
                if (DisableShowmount != null)
                {
                    writer.WritePropertyName("disableShowmount"u8);
                    writer.WriteBooleanValue(DisableShowmount.Value);
                }
                else
                {
                    writer.WriteNull("disableShowmount");
                }
            }
            if (Optional.IsDefined(NfsV4IdDomain))
            {
                if (NfsV4IdDomain != null)
                {
                    writer.WritePropertyName("nfsV4IDDomain"u8);
                    writer.WriteStringValue(NfsV4IdDomain);
                }
                else
                {
                    writer.WriteNull("nfsV4IDDomain");
                }
            }
            if (options.Format != "W" && Optional.IsDefined(MultiAdStatus))
            {
                writer.WritePropertyName("multiAdStatus"u8);
                writer.WriteStringValue(MultiAdStatus.Value.ToString());
            }
            writer.WriteEndObject();
        }

        NetAppAccountPatch IJsonModel<NetAppAccountPatch>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<NetAppAccountPatch>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(NetAppAccountPatch)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeNetAppAccountPatch(document.RootElement, options);
        }

        internal static NetAppAccountPatch DeserializeNetAppAccountPatch(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            ManagedServiceIdentity identity = default;
            IDictionary<string, string> tags = default;
            AzureLocation location = default;
            ResourceIdentifier id = default;
            string name = default;
            ResourceType type = default;
            SystemData systemData = default;
            string provisioningState = default;
            IList<NetAppAccountActiveDirectory> activeDirectories = default;
            NetAppAccountEncryption encryption = default;
            bool? disableShowmount = default;
            string nfsV4IdDomain = default;
            MultiAdStatus? multiAdStatus = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("identity"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    identity = ModelReaderWriter.Read<ManagedServiceIdentity>(new BinaryData(Encoding.UTF8.GetBytes(property.Value.GetRawText())), ModelSerializationExtensions.WireV3Options, AzureResourceManagerNetAppContext.Default);
                    continue;
                }
                if (property.NameEquals("tags"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    Dictionary<string, string> dictionary = new Dictionary<string, string>();
                    foreach (var property0 in property.Value.EnumerateObject())
                    {
                        dictionary.Add(property0.Name, property0.Value.GetString());
                    }
                    tags = dictionary;
                    continue;
                }
                if (property.NameEquals("location"u8))
                {
                    location = new AzureLocation(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("id"u8))
                {
                    id = new ResourceIdentifier(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("name"u8))
                {
                    name = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("type"u8))
                {
                    type = new ResourceType(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("systemData"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    systemData = ModelReaderWriter.Read<SystemData>(new BinaryData(Encoding.UTF8.GetBytes(property.Value.GetRawText())), ModelSerializationExtensions.WireOptions, AzureResourceManagerNetAppContext.Default);
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
                        if (property0.NameEquals("provisioningState"u8))
                        {
                            provisioningState = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("activeDirectories"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            List<NetAppAccountActiveDirectory> array = new List<NetAppAccountActiveDirectory>();
                            foreach (var item in property0.Value.EnumerateArray())
                            {
                                array.Add(NetAppAccountActiveDirectory.DeserializeNetAppAccountActiveDirectory(item, options));
                            }
                            activeDirectories = array;
                            continue;
                        }
                        if (property0.NameEquals("encryption"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            encryption = NetAppAccountEncryption.DeserializeNetAppAccountEncryption(property0.Value, options);
                            continue;
                        }
                        if (property0.NameEquals("disableShowmount"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                disableShowmount = null;
                                continue;
                            }
                            disableShowmount = property0.Value.GetBoolean();
                            continue;
                        }
                        if (property0.NameEquals("nfsV4IDDomain"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                nfsV4IdDomain = null;
                                continue;
                            }
                            nfsV4IdDomain = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("multiAdStatus"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            multiAdStatus = new MultiAdStatus(property0.Value.GetString());
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
            return new NetAppAccountPatch(
                id,
                name,
                type,
                systemData,
                tags ?? new ChangeTrackingDictionary<string, string>(),
                location,
                identity,
                provisioningState,
                activeDirectories ?? new ChangeTrackingList<NetAppAccountActiveDirectory>(),
                encryption,
                disableShowmount,
                nfsV4IdDomain,
                multiAdStatus,
                serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<NetAppAccountPatch>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<NetAppAccountPatch>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerNetAppContext.Default);
                default:
                    throw new FormatException($"The model {nameof(NetAppAccountPatch)} does not support writing '{options.Format}' format.");
            }
        }

        NetAppAccountPatch IPersistableModel<NetAppAccountPatch>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<NetAppAccountPatch>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeNetAppAccountPatch(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(NetAppAccountPatch)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<NetAppAccountPatch>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
