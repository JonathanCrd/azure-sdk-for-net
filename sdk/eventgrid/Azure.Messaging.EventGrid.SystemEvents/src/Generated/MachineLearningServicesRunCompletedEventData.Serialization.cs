// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;

namespace Azure.Messaging.EventGrid.SystemEvents
{
    [JsonConverter(typeof(MachineLearningServicesRunCompletedEventDataConverter))]
    public partial class MachineLearningServicesRunCompletedEventData : IUtf8JsonSerializable, IJsonModel<MachineLearningServicesRunCompletedEventData>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<MachineLearningServicesRunCompletedEventData>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<MachineLearningServicesRunCompletedEventData>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MachineLearningServicesRunCompletedEventData>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(MachineLearningServicesRunCompletedEventData)} does not support writing '{format}' format.");
            }

            writer.WritePropertyName("experimentId"u8);
            writer.WriteStringValue(ExperimentId);
            writer.WritePropertyName("experimentName"u8);
            writer.WriteStringValue(ExperimentName);
            writer.WritePropertyName("runId"u8);
            writer.WriteStringValue(RunId);
            writer.WritePropertyName("runType"u8);
            writer.WriteStringValue(RunType);
            if (Optional.IsDefined(RunTags))
            {
                writer.WritePropertyName("runTags"u8);
                writer.WriteObjectValue<object>(RunTags, options);
            }
            if (Optional.IsDefined(RunProperties))
            {
                writer.WritePropertyName("runProperties"u8);
                writer.WriteObjectValue<object>(RunProperties, options);
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

        MachineLearningServicesRunCompletedEventData IJsonModel<MachineLearningServicesRunCompletedEventData>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MachineLearningServicesRunCompletedEventData>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(MachineLearningServicesRunCompletedEventData)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeMachineLearningServicesRunCompletedEventData(document.RootElement, options);
        }

        internal static MachineLearningServicesRunCompletedEventData DeserializeMachineLearningServicesRunCompletedEventData(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string experimentId = default;
            string experimentName = default;
            string runId = default;
            string runType = default;
            object runTags = default;
            object runProperties = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("experimentId"u8))
                {
                    experimentId = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("experimentName"u8))
                {
                    experimentName = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("runId"u8))
                {
                    runId = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("runType"u8))
                {
                    runType = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("runTags"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    runTags = property.Value.GetObject();
                    continue;
                }
                if (property.NameEquals("runProperties"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    runProperties = property.Value.GetObject();
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new MachineLearningServicesRunCompletedEventData(
                experimentId,
                experimentName,
                runId,
                runType,
                runTags,
                runProperties,
                serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<MachineLearningServicesRunCompletedEventData>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MachineLearningServicesRunCompletedEventData>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureMessagingEventGridSystemEventsContext.Default);
                default:
                    throw new FormatException($"The model {nameof(MachineLearningServicesRunCompletedEventData)} does not support writing '{options.Format}' format.");
            }
        }

        MachineLearningServicesRunCompletedEventData IPersistableModel<MachineLearningServicesRunCompletedEventData>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MachineLearningServicesRunCompletedEventData>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeMachineLearningServicesRunCompletedEventData(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(MachineLearningServicesRunCompletedEventData)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<MachineLearningServicesRunCompletedEventData>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";

        /// <summary> Deserializes the model from a raw response. </summary>
        /// <param name="response"> The response to deserialize the model from. </param>
        internal static MachineLearningServicesRunCompletedEventData FromResponse(Response response)
        {
            using var document = JsonDocument.Parse(response.Content, ModelSerializationExtensions.JsonDocumentOptions);
            return DeserializeMachineLearningServicesRunCompletedEventData(document.RootElement);
        }

        /// <summary> Convert into a <see cref="RequestContent"/>. </summary>
        internal virtual RequestContent ToRequestContent()
        {
            var content = new Utf8JsonRequestContent();
            content.JsonWriter.WriteObjectValue(this, ModelSerializationExtensions.WireOptions);
            return content;
        }

        internal partial class MachineLearningServicesRunCompletedEventDataConverter : JsonConverter<MachineLearningServicesRunCompletedEventData>
        {
            public override void Write(Utf8JsonWriter writer, MachineLearningServicesRunCompletedEventData model, JsonSerializerOptions options)
            {
                writer.WriteObjectValue(model, ModelSerializationExtensions.WireOptions);
            }

            public override MachineLearningServicesRunCompletedEventData Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                using var document = JsonDocument.ParseValue(ref reader);
                return DeserializeMachineLearningServicesRunCompletedEventData(document.RootElement);
            }
        }
    }
}
