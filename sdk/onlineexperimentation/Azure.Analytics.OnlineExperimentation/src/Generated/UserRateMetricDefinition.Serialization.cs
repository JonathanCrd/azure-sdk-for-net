// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.Analytics.OnlineExperimentation
{
    public partial class UserRateMetricDefinition : IUtf8JsonSerializable, IJsonModel<UserRateMetricDefinition>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<UserRateMetricDefinition>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<UserRateMetricDefinition>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected override void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<UserRateMetricDefinition>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(UserRateMetricDefinition)} does not support writing '{format}' format.");
            }

            base.JsonModelWriteCore(writer, options);
            writer.WritePropertyName("startEvent"u8);
            writer.WriteObjectValue(StartEvent, options);
            writer.WritePropertyName("endEvent"u8);
            writer.WriteObjectValue(EndEvent, options);
        }

        UserRateMetricDefinition IJsonModel<UserRateMetricDefinition>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<UserRateMetricDefinition>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(UserRateMetricDefinition)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeUserRateMetricDefinition(document.RootElement, options);
        }

        internal static UserRateMetricDefinition DeserializeUserRateMetricDefinition(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            ObservedEvent startEvent = default;
            ObservedEvent endEvent = default;
            ExperimentMetricType type = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("startEvent"u8))
                {
                    startEvent = ObservedEvent.DeserializeObservedEvent(property.Value, options);
                    continue;
                }
                if (property.NameEquals("endEvent"u8))
                {
                    endEvent = ObservedEvent.DeserializeObservedEvent(property.Value, options);
                    continue;
                }
                if (property.NameEquals("type"u8))
                {
                    type = new ExperimentMetricType(property.Value.GetString());
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new UserRateMetricDefinition(type, serializedAdditionalRawData, startEvent, endEvent);
        }

        BinaryData IPersistableModel<UserRateMetricDefinition>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<UserRateMetricDefinition>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureAnalyticsOnlineExperimentationContext.Default);
                default:
                    throw new FormatException($"The model {nameof(UserRateMetricDefinition)} does not support writing '{options.Format}' format.");
            }
        }

        UserRateMetricDefinition IPersistableModel<UserRateMetricDefinition>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<UserRateMetricDefinition>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeUserRateMetricDefinition(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(UserRateMetricDefinition)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<UserRateMetricDefinition>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";

        /// <summary> Deserializes the model from a raw response. </summary>
        /// <param name="response"> The response to deserialize the model from. </param>
        internal static new UserRateMetricDefinition FromResponse(Response response)
        {
            using var document = JsonDocument.Parse(response.Content, ModelSerializationExtensions.JsonDocumentOptions);
            return DeserializeUserRateMetricDefinition(document.RootElement);
        }

        /// <summary> Convert into a <see cref="RequestContent"/>. </summary>
        internal override RequestContent ToRequestContent()
        {
            var content = new Utf8JsonRequestContent();
            content.JsonWriter.WriteObjectValue(this, ModelSerializationExtensions.WireOptions);
            return content;
        }
    }
}
