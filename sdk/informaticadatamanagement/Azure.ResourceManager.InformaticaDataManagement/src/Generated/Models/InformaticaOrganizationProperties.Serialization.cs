// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.InformaticaDataManagement.Models
{
    public partial class InformaticaOrganizationProperties : IUtf8JsonSerializable, IJsonModel<InformaticaOrganizationProperties>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<InformaticaOrganizationProperties>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<InformaticaOrganizationProperties>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<InformaticaOrganizationProperties>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(InformaticaOrganizationProperties)} does not support writing '{format}' format.");
            }

            if (options.Format != "W" && Optional.IsDefined(ProvisioningState))
            {
                writer.WritePropertyName("provisioningState"u8);
                writer.WriteStringValue(ProvisioningState.Value.ToString());
            }
            if (Optional.IsDefined(InformaticaProperties))
            {
                writer.WritePropertyName("informaticaProperties"u8);
                writer.WriteObjectValue(InformaticaProperties, options);
            }
            if (Optional.IsDefined(MarketplaceDetails))
            {
                writer.WritePropertyName("marketplaceDetails"u8);
                writer.WriteObjectValue(MarketplaceDetails, options);
            }
            if (Optional.IsDefined(UserDetails))
            {
                writer.WritePropertyName("userDetails"u8);
                writer.WriteObjectValue(UserDetails, options);
            }
            if (Optional.IsDefined(CompanyDetails))
            {
                writer.WritePropertyName("companyDetails"u8);
                writer.WriteObjectValue(CompanyDetails, options);
            }
            if (Optional.IsDefined(LinkOrganization))
            {
                writer.WritePropertyName("linkOrganization"u8);
                writer.WriteObjectValue(LinkOrganization, options);
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

        InformaticaOrganizationProperties IJsonModel<InformaticaOrganizationProperties>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<InformaticaOrganizationProperties>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(InformaticaOrganizationProperties)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeInformaticaOrganizationProperties(document.RootElement, options);
        }

        internal static InformaticaOrganizationProperties DeserializeInformaticaOrganizationProperties(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            InformaticaProvisioningState? provisioningState = default;
            InformaticaProperties informaticaProperties = default;
            InformaticaMarketplaceDetails marketplaceDetails = default;
            InformaticaUserDetails userDetails = default;
            InformaticaCompanyDetails companyDetails = default;
            LinkOrganization linkOrganization = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("provisioningState"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    provisioningState = new InformaticaProvisioningState(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("informaticaProperties"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    informaticaProperties = InformaticaProperties.DeserializeInformaticaProperties(property.Value, options);
                    continue;
                }
                if (property.NameEquals("marketplaceDetails"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    marketplaceDetails = InformaticaMarketplaceDetails.DeserializeInformaticaMarketplaceDetails(property.Value, options);
                    continue;
                }
                if (property.NameEquals("userDetails"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    userDetails = InformaticaUserDetails.DeserializeInformaticaUserDetails(property.Value, options);
                    continue;
                }
                if (property.NameEquals("companyDetails"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    companyDetails = InformaticaCompanyDetails.DeserializeInformaticaCompanyDetails(property.Value, options);
                    continue;
                }
                if (property.NameEquals("linkOrganization"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    linkOrganization = LinkOrganization.DeserializeLinkOrganization(property.Value, options);
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new InformaticaOrganizationProperties(
                provisioningState,
                informaticaProperties,
                marketplaceDetails,
                userDetails,
                companyDetails,
                linkOrganization,
                serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<InformaticaOrganizationProperties>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<InformaticaOrganizationProperties>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerInformaticaDataManagementContext.Default);
                default:
                    throw new FormatException($"The model {nameof(InformaticaOrganizationProperties)} does not support writing '{options.Format}' format.");
            }
        }

        InformaticaOrganizationProperties IPersistableModel<InformaticaOrganizationProperties>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<InformaticaOrganizationProperties>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeInformaticaOrganizationProperties(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(InformaticaOrganizationProperties)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<InformaticaOrganizationProperties>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
