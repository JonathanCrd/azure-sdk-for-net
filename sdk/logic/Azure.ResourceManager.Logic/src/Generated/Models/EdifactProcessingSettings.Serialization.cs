// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.Logic.Models
{
    public partial class EdifactProcessingSettings : IUtf8JsonSerializable, IJsonModel<EdifactProcessingSettings>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<EdifactProcessingSettings>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<EdifactProcessingSettings>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<EdifactProcessingSettings>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(EdifactProcessingSettings)} does not support writing '{format}' format.");
            }

            writer.WritePropertyName("maskSecurityInfo"u8);
            writer.WriteBooleanValue(MaskSecurityInfo);
            writer.WritePropertyName("preserveInterchange"u8);
            writer.WriteBooleanValue(PreserveInterchange);
            writer.WritePropertyName("suspendInterchangeOnError"u8);
            writer.WriteBooleanValue(SuspendInterchangeOnError);
            writer.WritePropertyName("createEmptyXmlTagsForTrailingSeparators"u8);
            writer.WriteBooleanValue(CreateEmptyXmlTagsForTrailingSeparators);
            writer.WritePropertyName("useDotAsDecimalSeparator"u8);
            writer.WriteBooleanValue(UseDotAsDecimalSeparator);
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

        EdifactProcessingSettings IJsonModel<EdifactProcessingSettings>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<EdifactProcessingSettings>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(EdifactProcessingSettings)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeEdifactProcessingSettings(document.RootElement, options);
        }

        internal static EdifactProcessingSettings DeserializeEdifactProcessingSettings(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            bool maskSecurityInfo = default;
            bool preserveInterchange = default;
            bool suspendInterchangeOnError = default;
            bool createEmptyXmlTagsForTrailingSeparators = default;
            bool useDotAsDecimalSeparator = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("maskSecurityInfo"u8))
                {
                    maskSecurityInfo = property.Value.GetBoolean();
                    continue;
                }
                if (property.NameEquals("preserveInterchange"u8))
                {
                    preserveInterchange = property.Value.GetBoolean();
                    continue;
                }
                if (property.NameEquals("suspendInterchangeOnError"u8))
                {
                    suspendInterchangeOnError = property.Value.GetBoolean();
                    continue;
                }
                if (property.NameEquals("createEmptyXmlTagsForTrailingSeparators"u8))
                {
                    createEmptyXmlTagsForTrailingSeparators = property.Value.GetBoolean();
                    continue;
                }
                if (property.NameEquals("useDotAsDecimalSeparator"u8))
                {
                    useDotAsDecimalSeparator = property.Value.GetBoolean();
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new EdifactProcessingSettings(
                maskSecurityInfo,
                preserveInterchange,
                suspendInterchangeOnError,
                createEmptyXmlTagsForTrailingSeparators,
                useDotAsDecimalSeparator,
                serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<EdifactProcessingSettings>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<EdifactProcessingSettings>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerLogicContext.Default);
                default:
                    throw new FormatException($"The model {nameof(EdifactProcessingSettings)} does not support writing '{options.Format}' format.");
            }
        }

        EdifactProcessingSettings IPersistableModel<EdifactProcessingSettings>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<EdifactProcessingSettings>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeEdifactProcessingSettings(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(EdifactProcessingSettings)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<EdifactProcessingSettings>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
