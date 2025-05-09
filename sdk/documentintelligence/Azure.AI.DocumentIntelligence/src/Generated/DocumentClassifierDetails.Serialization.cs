// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.AI.DocumentIntelligence
{
    public partial class DocumentClassifierDetails : IUtf8JsonSerializable, IJsonModel<DocumentClassifierDetails>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<DocumentClassifierDetails>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<DocumentClassifierDetails>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<DocumentClassifierDetails>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(DocumentClassifierDetails)} does not support writing '{format}' format.");
            }

            writer.WritePropertyName("classifierId"u8);
            writer.WriteStringValue(ClassifierId);
            if (Optional.IsDefined(Description))
            {
                writer.WritePropertyName("description"u8);
                writer.WriteStringValue(Description);
            }
            writer.WritePropertyName("createdDateTime"u8);
            writer.WriteStringValue(CreatedOn, "O");
            if (Optional.IsDefined(ExpiresOn))
            {
                writer.WritePropertyName("expirationDateTime"u8);
                writer.WriteStringValue(ExpiresOn.Value, "O");
            }
            if (options.Format != "W" && Optional.IsDefined(ModifiedOn))
            {
                writer.WritePropertyName("modifiedDateTime"u8);
                writer.WriteStringValue(ModifiedOn.Value, "O");
            }
            writer.WritePropertyName("apiVersion"u8);
            writer.WriteStringValue(ApiVersion);
            if (Optional.IsDefined(BaseClassifierId))
            {
                writer.WritePropertyName("baseClassifierId"u8);
                writer.WriteStringValue(BaseClassifierId);
            }
            writer.WritePropertyName("docTypes"u8);
            writer.WriteStartObject();
            foreach (var item in DocumentTypes)
            {
                writer.WritePropertyName(item.Key);
                writer.WriteObjectValue(item.Value, options);
            }
            writer.WriteEndObject();
            if (Optional.IsCollectionDefined(Warnings))
            {
                writer.WritePropertyName("warnings"u8);
                writer.WriteStartArray();
                foreach (var item in Warnings)
                {
                    writer.WriteObjectValue(item, options);
                }
                writer.WriteEndArray();
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

        DocumentClassifierDetails IJsonModel<DocumentClassifierDetails>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<DocumentClassifierDetails>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(DocumentClassifierDetails)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeDocumentClassifierDetails(document.RootElement, options);
        }

        internal static DocumentClassifierDetails DeserializeDocumentClassifierDetails(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string classifierId = default;
            string description = default;
            DateTimeOffset createdDateTime = default;
            DateTimeOffset? expirationDateTime = default;
            DateTimeOffset? modifiedDateTime = default;
            string apiVersion = default;
            string baseClassifierId = default;
            IReadOnlyDictionary<string, ClassifierDocumentTypeDetails> docTypes = default;
            IReadOnlyList<DocumentIntelligenceWarning> warnings = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("classifierId"u8))
                {
                    classifierId = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("description"u8))
                {
                    description = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("createdDateTime"u8))
                {
                    createdDateTime = property.Value.GetDateTimeOffset("O");
                    continue;
                }
                if (property.NameEquals("expirationDateTime"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    expirationDateTime = property.Value.GetDateTimeOffset("O");
                    continue;
                }
                if (property.NameEquals("modifiedDateTime"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    modifiedDateTime = property.Value.GetDateTimeOffset("O");
                    continue;
                }
                if (property.NameEquals("apiVersion"u8))
                {
                    apiVersion = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("baseClassifierId"u8))
                {
                    baseClassifierId = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("docTypes"u8))
                {
                    Dictionary<string, ClassifierDocumentTypeDetails> dictionary = new Dictionary<string, ClassifierDocumentTypeDetails>();
                    foreach (var property0 in property.Value.EnumerateObject())
                    {
                        dictionary.Add(property0.Name, ClassifierDocumentTypeDetails.DeserializeClassifierDocumentTypeDetails(property0.Value, options));
                    }
                    docTypes = dictionary;
                    continue;
                }
                if (property.NameEquals("warnings"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    List<DocumentIntelligenceWarning> array = new List<DocumentIntelligenceWarning>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(DocumentIntelligenceWarning.DeserializeDocumentIntelligenceWarning(item, options));
                    }
                    warnings = array;
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new DocumentClassifierDetails(
                classifierId,
                description,
                createdDateTime,
                expirationDateTime,
                modifiedDateTime,
                apiVersion,
                baseClassifierId,
                docTypes,
                warnings ?? new ChangeTrackingList<DocumentIntelligenceWarning>(),
                serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<DocumentClassifierDetails>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<DocumentClassifierDetails>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureAIDocumentIntelligenceContext.Default);
                default:
                    throw new FormatException($"The model {nameof(DocumentClassifierDetails)} does not support writing '{options.Format}' format.");
            }
        }

        DocumentClassifierDetails IPersistableModel<DocumentClassifierDetails>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<DocumentClassifierDetails>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeDocumentClassifierDetails(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(DocumentClassifierDetails)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<DocumentClassifierDetails>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";

        /// <summary> Deserializes the model from a raw response. </summary>
        /// <param name="response"> The response to deserialize the model from. </param>
        internal static DocumentClassifierDetails FromResponse(Response response)
        {
            using var document = JsonDocument.Parse(response.Content, ModelSerializationExtensions.JsonDocumentOptions);
            return DeserializeDocumentClassifierDetails(document.RootElement);
        }

        /// <summary> Convert into a <see cref="RequestContent"/>. </summary>
        internal virtual RequestContent ToRequestContent()
        {
            var content = new Utf8JsonRequestContent();
            content.JsonWriter.WriteObjectValue(this, ModelSerializationExtensions.WireOptions);
            return content;
        }
    }
}
