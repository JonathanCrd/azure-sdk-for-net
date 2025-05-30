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

namespace Azure.ResourceManager.DesktopVirtualization.Models
{
    public partial class MaintenanceWindowPatchProperties : IUtf8JsonSerializable, IJsonModel<MaintenanceWindowPatchProperties>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<MaintenanceWindowPatchProperties>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<MaintenanceWindowPatchProperties>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MaintenanceWindowPatchProperties>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(MaintenanceWindowPatchProperties)} does not support writing '{format}' format.");
            }

            if (Optional.IsDefined(Hour))
            {
                writer.WritePropertyName("hour"u8);
                writer.WriteNumberValue(Hour.Value);
            }
            if (Optional.IsDefined(DayOfWeek))
            {
                writer.WritePropertyName("dayOfWeek"u8);
                writer.WriteStringValue(DayOfWeek.Value.ToSerialString());
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

        MaintenanceWindowPatchProperties IJsonModel<MaintenanceWindowPatchProperties>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MaintenanceWindowPatchProperties>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(MaintenanceWindowPatchProperties)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeMaintenanceWindowPatchProperties(document.RootElement, options);
        }

        internal static MaintenanceWindowPatchProperties DeserializeMaintenanceWindowPatchProperties(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            int? hour = default;
            DesktopVirtualizationDayOfWeek? dayOfWeek = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("hour"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    hour = property.Value.GetInt32();
                    continue;
                }
                if (property.NameEquals("dayOfWeek"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    dayOfWeek = property.Value.GetString().ToDesktopVirtualizationDayOfWeek();
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new MaintenanceWindowPatchProperties(hour, dayOfWeek, serializedAdditionalRawData);
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

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(Hour), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  hour: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(Hour))
                {
                    builder.Append("  hour: ");
                    builder.AppendLine($"{Hour.Value}");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(DayOfWeek), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  dayOfWeek: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(DayOfWeek))
                {
                    builder.Append("  dayOfWeek: ");
                    builder.AppendLine($"'{DayOfWeek.Value.ToSerialString()}'");
                }
            }

            builder.AppendLine("}");
            return BinaryData.FromString(builder.ToString());
        }

        BinaryData IPersistableModel<MaintenanceWindowPatchProperties>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MaintenanceWindowPatchProperties>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerDesktopVirtualizationContext.Default);
                case "bicep":
                    return SerializeBicep(options);
                default:
                    throw new FormatException($"The model {nameof(MaintenanceWindowPatchProperties)} does not support writing '{options.Format}' format.");
            }
        }

        MaintenanceWindowPatchProperties IPersistableModel<MaintenanceWindowPatchProperties>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MaintenanceWindowPatchProperties>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeMaintenanceWindowPatchProperties(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(MaintenanceWindowPatchProperties)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<MaintenanceWindowPatchProperties>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
