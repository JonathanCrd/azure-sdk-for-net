// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.Migration.Assessment.Models
{
    public partial class AssessedNetworkAdapter : IUtf8JsonSerializable, IJsonModel<AssessedNetworkAdapter>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<AssessedNetworkAdapter>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<AssessedNetworkAdapter>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AssessedNetworkAdapter>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(AssessedNetworkAdapter)} does not support writing '{format}' format.");
            }

            if (Optional.IsDefined(Suitability))
            {
                writer.WritePropertyName("suitability"u8);
                writer.WriteStringValue(Suitability.Value.ToString());
            }
            if (Optional.IsDefined(SuitabilityDetail))
            {
                writer.WritePropertyName("suitabilityDetail"u8);
                writer.WriteStringValue(SuitabilityDetail.Value.ToString());
            }
            if (Optional.IsDefined(SuitabilityExplanation))
            {
                writer.WritePropertyName("suitabilityExplanation"u8);
                writer.WriteStringValue(SuitabilityExplanation.Value.ToString());
            }
            if (Optional.IsDefined(MonthlyBandwidthCosts))
            {
                writer.WritePropertyName("monthlyBandwidthCosts"u8);
                writer.WriteNumberValue(MonthlyBandwidthCosts.Value);
            }
            if (Optional.IsDefined(NetGigabytesTransmittedPerMonth))
            {
                writer.WritePropertyName("netGigabytesTransmittedPerMonth"u8);
                writer.WriteNumberValue(NetGigabytesTransmittedPerMonth.Value);
            }
            if (Optional.IsDefined(DisplayName))
            {
                writer.WritePropertyName("displayName"u8);
                writer.WriteStringValue(DisplayName);
            }
            if (Optional.IsDefined(MacAddress))
            {
                writer.WritePropertyName("macAddress"u8);
                writer.WriteStringValue(MacAddress);
            }
            if (options.Format != "W" && Optional.IsCollectionDefined(IPAddresses))
            {
                writer.WritePropertyName("ipAddresses"u8);
                writer.WriteStartArray();
                foreach (var item in IPAddresses)
                {
                    writer.WriteStringValue(item);
                }
                writer.WriteEndArray();
            }
            if (Optional.IsDefined(MegabytesPerSecondReceived))
            {
                writer.WritePropertyName("megabytesPerSecondReceived"u8);
                writer.WriteNumberValue(MegabytesPerSecondReceived.Value);
            }
            if (Optional.IsDefined(MegabytesPerSecondTransmitted))
            {
                writer.WritePropertyName("megabytesPerSecondTransmitted"u8);
                writer.WriteNumberValue(MegabytesPerSecondTransmitted.Value);
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

        AssessedNetworkAdapter IJsonModel<AssessedNetworkAdapter>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AssessedNetworkAdapter>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(AssessedNetworkAdapter)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeAssessedNetworkAdapter(document.RootElement, options);
        }

        internal static AssessedNetworkAdapter DeserializeAssessedNetworkAdapter(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            MigrationAssessmentCloudSuitability? suitability = default;
            NetworkAdapterSuitabilityDetail? suitabilityDetail = default;
            NetworkAdapterSuitabilityExplanation? suitabilityExplanation = default;
            double? monthlyBandwidthCosts = default;
            double? netGigabytesTransmittedPerMonth = default;
            string displayName = default;
            string macAddress = default;
            IReadOnlyList<string> ipAddresses = default;
            double? megabytesPerSecondReceived = default;
            double? megabytesPerSecondTransmitted = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("suitability"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    suitability = new MigrationAssessmentCloudSuitability(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("suitabilityDetail"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    suitabilityDetail = new NetworkAdapterSuitabilityDetail(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("suitabilityExplanation"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    suitabilityExplanation = new NetworkAdapterSuitabilityExplanation(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("monthlyBandwidthCosts"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    monthlyBandwidthCosts = property.Value.GetDouble();
                    continue;
                }
                if (property.NameEquals("netGigabytesTransmittedPerMonth"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    netGigabytesTransmittedPerMonth = property.Value.GetDouble();
                    continue;
                }
                if (property.NameEquals("displayName"u8))
                {
                    displayName = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("macAddress"u8))
                {
                    macAddress = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("ipAddresses"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    List<string> array = new List<string>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(item.GetString());
                    }
                    ipAddresses = array;
                    continue;
                }
                if (property.NameEquals("megabytesPerSecondReceived"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    megabytesPerSecondReceived = property.Value.GetDouble();
                    continue;
                }
                if (property.NameEquals("megabytesPerSecondTransmitted"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    megabytesPerSecondTransmitted = property.Value.GetDouble();
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new AssessedNetworkAdapter(
                suitability,
                suitabilityDetail,
                suitabilityExplanation,
                monthlyBandwidthCosts,
                netGigabytesTransmittedPerMonth,
                displayName,
                macAddress,
                ipAddresses ?? new ChangeTrackingList<string>(),
                megabytesPerSecondReceived,
                megabytesPerSecondTransmitted,
                serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<AssessedNetworkAdapter>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AssessedNetworkAdapter>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerMigrationAssessmentContext.Default);
                default:
                    throw new FormatException($"The model {nameof(AssessedNetworkAdapter)} does not support writing '{options.Format}' format.");
            }
        }

        AssessedNetworkAdapter IPersistableModel<AssessedNetworkAdapter>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AssessedNetworkAdapter>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeAssessedNetworkAdapter(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(AssessedNetworkAdapter)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<AssessedNetworkAdapter>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
