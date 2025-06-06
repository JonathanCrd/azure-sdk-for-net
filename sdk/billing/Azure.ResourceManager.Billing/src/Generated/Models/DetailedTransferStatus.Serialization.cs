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

namespace Azure.ResourceManager.Billing.Models
{
    public partial class DetailedTransferStatus : IUtf8JsonSerializable, IJsonModel<DetailedTransferStatus>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<DetailedTransferStatus>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<DetailedTransferStatus>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<DetailedTransferStatus>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(DetailedTransferStatus)} does not support writing '{format}' format.");
            }

            if (options.Format != "W" && Optional.IsDefined(ProductType))
            {
                writer.WritePropertyName("productType"u8);
                writer.WriteStringValue(ProductType.Value.ToString());
            }
            if (options.Format != "W" && Optional.IsDefined(ProductId))
            {
                writer.WritePropertyName("productId"u8);
                writer.WriteStringValue(ProductId);
            }
            if (options.Format != "W" && Optional.IsDefined(ProductName))
            {
                writer.WritePropertyName("productName"u8);
                writer.WriteStringValue(ProductName);
            }
            if (options.Format != "W" && Optional.IsDefined(SkuDescription))
            {
                writer.WritePropertyName("skuDescription"u8);
                writer.WriteStringValue(SkuDescription);
            }
            if (options.Format != "W" && Optional.IsDefined(TransferStatus))
            {
                writer.WritePropertyName("transferStatus"u8);
                writer.WriteStringValue(TransferStatus.Value.ToString());
            }
            if (Optional.IsDefined(ErrorDetails))
            {
                writer.WritePropertyName("errorDetails"u8);
                writer.WriteObjectValue(ErrorDetails, options);
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

        DetailedTransferStatus IJsonModel<DetailedTransferStatus>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<DetailedTransferStatus>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(DetailedTransferStatus)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeDetailedTransferStatus(document.RootElement, options);
        }

        internal static DetailedTransferStatus DeserializeDetailedTransferStatus(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            BillingProductType? productType = default;
            string productId = default;
            string productName = default;
            string skuDescription = default;
            BillingProductTransferStatus? transferStatus = default;
            BillingTransferError errorDetails = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("productType"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    productType = new BillingProductType(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("productId"u8))
                {
                    productId = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("productName"u8))
                {
                    productName = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("skuDescription"u8))
                {
                    skuDescription = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("transferStatus"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    transferStatus = new BillingProductTransferStatus(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("errorDetails"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    errorDetails = BillingTransferError.DeserializeBillingTransferError(property.Value, options);
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new DetailedTransferStatus(
                productType,
                productId,
                productName,
                skuDescription,
                transferStatus,
                errorDetails,
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

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(ProductType), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  productType: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(ProductType))
                {
                    builder.Append("  productType: ");
                    builder.AppendLine($"'{ProductType.Value.ToString()}'");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(ProductId), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  productId: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(ProductId))
                {
                    builder.Append("  productId: ");
                    if (ProductId.Contains(Environment.NewLine))
                    {
                        builder.AppendLine("'''");
                        builder.AppendLine($"{ProductId}'''");
                    }
                    else
                    {
                        builder.AppendLine($"'{ProductId}'");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(ProductName), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  productName: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(ProductName))
                {
                    builder.Append("  productName: ");
                    if (ProductName.Contains(Environment.NewLine))
                    {
                        builder.AppendLine("'''");
                        builder.AppendLine($"{ProductName}'''");
                    }
                    else
                    {
                        builder.AppendLine($"'{ProductName}'");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(SkuDescription), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  skuDescription: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(SkuDescription))
                {
                    builder.Append("  skuDescription: ");
                    if (SkuDescription.Contains(Environment.NewLine))
                    {
                        builder.AppendLine("'''");
                        builder.AppendLine($"{SkuDescription}'''");
                    }
                    else
                    {
                        builder.AppendLine($"'{SkuDescription}'");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(TransferStatus), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  transferStatus: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(TransferStatus))
                {
                    builder.Append("  transferStatus: ");
                    builder.AppendLine($"'{TransferStatus.Value.ToString()}'");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(ErrorDetails), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  errorDetails: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(ErrorDetails))
                {
                    builder.Append("  errorDetails: ");
                    BicepSerializationHelpers.AppendChildObject(builder, ErrorDetails, options, 2, false, "  errorDetails: ");
                }
            }

            builder.AppendLine("}");
            return BinaryData.FromString(builder.ToString());
        }

        BinaryData IPersistableModel<DetailedTransferStatus>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<DetailedTransferStatus>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerBillingContext.Default);
                case "bicep":
                    return SerializeBicep(options);
                default:
                    throw new FormatException($"The model {nameof(DetailedTransferStatus)} does not support writing '{options.Format}' format.");
            }
        }

        DetailedTransferStatus IPersistableModel<DetailedTransferStatus>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<DetailedTransferStatus>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeDetailedTransferStatus(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(DetailedTransferStatus)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<DetailedTransferStatus>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
