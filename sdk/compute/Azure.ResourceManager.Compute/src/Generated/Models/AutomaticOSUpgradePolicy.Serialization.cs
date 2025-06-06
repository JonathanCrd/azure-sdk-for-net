// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.Compute.Models
{
    public partial class AutomaticOSUpgradePolicy : IUtf8JsonSerializable, IJsonModel<AutomaticOSUpgradePolicy>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<AutomaticOSUpgradePolicy>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<AutomaticOSUpgradePolicy>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AutomaticOSUpgradePolicy>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(AutomaticOSUpgradePolicy)} does not support writing '{format}' format.");
            }

            if (Optional.IsDefined(EnableAutomaticOSUpgrade))
            {
                writer.WritePropertyName("enableAutomaticOSUpgrade"u8);
                writer.WriteBooleanValue(EnableAutomaticOSUpgrade.Value);
            }
            if (Optional.IsDefined(DisableAutomaticRollback))
            {
                writer.WritePropertyName("disableAutomaticRollback"u8);
                writer.WriteBooleanValue(DisableAutomaticRollback.Value);
            }
            if (Optional.IsDefined(UseRollingUpgradePolicy))
            {
                writer.WritePropertyName("useRollingUpgradePolicy"u8);
                writer.WriteBooleanValue(UseRollingUpgradePolicy.Value);
            }
            if (Optional.IsDefined(OSRollingUpgradeDeferral))
            {
                writer.WritePropertyName("osRollingUpgradeDeferral"u8);
                writer.WriteBooleanValue(OSRollingUpgradeDeferral.Value);
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

        AutomaticOSUpgradePolicy IJsonModel<AutomaticOSUpgradePolicy>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AutomaticOSUpgradePolicy>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(AutomaticOSUpgradePolicy)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeAutomaticOSUpgradePolicy(document.RootElement, options);
        }

        internal static AutomaticOSUpgradePolicy DeserializeAutomaticOSUpgradePolicy(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            bool? enableAutomaticOSUpgrade = default;
            bool? disableAutomaticRollback = default;
            bool? useRollingUpgradePolicy = default;
            bool? osRollingUpgradeDeferral = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("enableAutomaticOSUpgrade"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    enableAutomaticOSUpgrade = property.Value.GetBoolean();
                    continue;
                }
                if (property.NameEquals("disableAutomaticRollback"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    disableAutomaticRollback = property.Value.GetBoolean();
                    continue;
                }
                if (property.NameEquals("useRollingUpgradePolicy"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    useRollingUpgradePolicy = property.Value.GetBoolean();
                    continue;
                }
                if (property.NameEquals("osRollingUpgradeDeferral"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    osRollingUpgradeDeferral = property.Value.GetBoolean();
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new AutomaticOSUpgradePolicy(enableAutomaticOSUpgrade, disableAutomaticRollback, useRollingUpgradePolicy, osRollingUpgradeDeferral, serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<AutomaticOSUpgradePolicy>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AutomaticOSUpgradePolicy>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerComputeContext.Default);
                default:
                    throw new FormatException($"The model {nameof(AutomaticOSUpgradePolicy)} does not support writing '{options.Format}' format.");
            }
        }

        AutomaticOSUpgradePolicy IPersistableModel<AutomaticOSUpgradePolicy>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<AutomaticOSUpgradePolicy>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeAutomaticOSUpgradePolicy(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(AutomaticOSUpgradePolicy)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<AutomaticOSUpgradePolicy>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
