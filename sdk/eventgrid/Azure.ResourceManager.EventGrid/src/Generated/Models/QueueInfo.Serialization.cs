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

namespace Azure.ResourceManager.EventGrid.Models
{
    public partial class QueueInfo : IUtf8JsonSerializable, IJsonModel<QueueInfo>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<QueueInfo>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<QueueInfo>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<QueueInfo>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(QueueInfo)} does not support writing '{format}' format.");
            }

            if (Optional.IsDefined(ReceiveLockDurationInSeconds))
            {
                writer.WritePropertyName("receiveLockDurationInSeconds"u8);
                writer.WriteNumberValue(ReceiveLockDurationInSeconds.Value);
            }
            if (Optional.IsDefined(MaxDeliveryCount))
            {
                writer.WritePropertyName("maxDeliveryCount"u8);
                writer.WriteNumberValue(MaxDeliveryCount.Value);
            }
            if (Optional.IsDefined(DeadLetterDestinationWithResourceIdentity))
            {
                writer.WritePropertyName("deadLetterDestinationWithResourceIdentity"u8);
                writer.WriteObjectValue(DeadLetterDestinationWithResourceIdentity, options);
            }
            if (Optional.IsDefined(EventTimeToLive))
            {
                writer.WritePropertyName("eventTimeToLive"u8);
                writer.WriteStringValue(EventTimeToLive.Value, "P");
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

        QueueInfo IJsonModel<QueueInfo>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<QueueInfo>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(QueueInfo)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeQueueInfo(document.RootElement, options);
        }

        internal static QueueInfo DeserializeQueueInfo(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            int? receiveLockDurationInSeconds = default;
            int? maxDeliveryCount = default;
            DeadLetterWithResourceIdentity deadLetterDestinationWithResourceIdentity = default;
            TimeSpan? eventTimeToLive = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("receiveLockDurationInSeconds"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    receiveLockDurationInSeconds = property.Value.GetInt32();
                    continue;
                }
                if (property.NameEquals("maxDeliveryCount"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    maxDeliveryCount = property.Value.GetInt32();
                    continue;
                }
                if (property.NameEquals("deadLetterDestinationWithResourceIdentity"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    deadLetterDestinationWithResourceIdentity = DeadLetterWithResourceIdentity.DeserializeDeadLetterWithResourceIdentity(property.Value, options);
                    continue;
                }
                if (property.NameEquals("eventTimeToLive"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    eventTimeToLive = property.Value.GetTimeSpan("P");
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new QueueInfo(receiveLockDurationInSeconds, maxDeliveryCount, deadLetterDestinationWithResourceIdentity, eventTimeToLive, serializedAdditionalRawData);
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

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(ReceiveLockDurationInSeconds), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  receiveLockDurationInSeconds: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(ReceiveLockDurationInSeconds))
                {
                    builder.Append("  receiveLockDurationInSeconds: ");
                    builder.AppendLine($"{ReceiveLockDurationInSeconds.Value}");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(MaxDeliveryCount), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  maxDeliveryCount: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(MaxDeliveryCount))
                {
                    builder.Append("  maxDeliveryCount: ");
                    builder.AppendLine($"{MaxDeliveryCount.Value}");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(DeadLetterDestinationWithResourceIdentity), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  deadLetterDestinationWithResourceIdentity: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(DeadLetterDestinationWithResourceIdentity))
                {
                    builder.Append("  deadLetterDestinationWithResourceIdentity: ");
                    BicepSerializationHelpers.AppendChildObject(builder, DeadLetterDestinationWithResourceIdentity, options, 2, false, "  deadLetterDestinationWithResourceIdentity: ");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(EventTimeToLive), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  eventTimeToLive: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(EventTimeToLive))
                {
                    builder.Append("  eventTimeToLive: ");
                    var formattedTimeSpan = TypeFormatters.ToString(EventTimeToLive.Value, "P");
                    builder.AppendLine($"'{formattedTimeSpan}'");
                }
            }

            builder.AppendLine("}");
            return BinaryData.FromString(builder.ToString());
        }

        BinaryData IPersistableModel<QueueInfo>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<QueueInfo>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerEventGridContext.Default);
                case "bicep":
                    return SerializeBicep(options);
                default:
                    throw new FormatException($"The model {nameof(QueueInfo)} does not support writing '{options.Format}' format.");
            }
        }

        QueueInfo IPersistableModel<QueueInfo>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<QueueInfo>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeQueueInfo(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(QueueInfo)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<QueueInfo>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
