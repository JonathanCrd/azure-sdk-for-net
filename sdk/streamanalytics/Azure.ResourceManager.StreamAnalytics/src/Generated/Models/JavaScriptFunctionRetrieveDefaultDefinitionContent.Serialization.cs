// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.StreamAnalytics.Models
{
    public partial class JavaScriptFunctionRetrieveDefaultDefinitionContent : IUtf8JsonSerializable, IJsonModel<JavaScriptFunctionRetrieveDefaultDefinitionContent>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<JavaScriptFunctionRetrieveDefaultDefinitionContent>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<JavaScriptFunctionRetrieveDefaultDefinitionContent>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected override void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<JavaScriptFunctionRetrieveDefaultDefinitionContent>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(JavaScriptFunctionRetrieveDefaultDefinitionContent)} does not support writing '{format}' format.");
            }

            base.JsonModelWriteCore(writer, options);
            writer.WritePropertyName("bindingRetrievalProperties"u8);
            writer.WriteStartObject();
            if (Optional.IsDefined(Script))
            {
                writer.WritePropertyName("script"u8);
                writer.WriteStringValue(Script);
            }
            if (Optional.IsDefined(UdfType))
            {
                writer.WritePropertyName("udfType"u8);
                writer.WriteStringValue(UdfType.Value.ToString());
            }
            writer.WriteEndObject();
        }

        JavaScriptFunctionRetrieveDefaultDefinitionContent IJsonModel<JavaScriptFunctionRetrieveDefaultDefinitionContent>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<JavaScriptFunctionRetrieveDefaultDefinitionContent>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(JavaScriptFunctionRetrieveDefaultDefinitionContent)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeJavaScriptFunctionRetrieveDefaultDefinitionContent(document.RootElement, options);
        }

        internal static JavaScriptFunctionRetrieveDefaultDefinitionContent DeserializeJavaScriptFunctionRetrieveDefaultDefinitionContent(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string bindingType = default;
            string script = default;
            StreamingJobFunctionUdfType? udfType = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("bindingType"u8))
                {
                    bindingType = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("bindingRetrievalProperties"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        property.ThrowNonNullablePropertyIsNull();
                        continue;
                    }
                    foreach (var property0 in property.Value.EnumerateObject())
                    {
                        if (property0.NameEquals("script"u8))
                        {
                            script = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("udfType"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            udfType = new StreamingJobFunctionUdfType(property0.Value.GetString());
                            continue;
                        }
                    }
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new JavaScriptFunctionRetrieveDefaultDefinitionContent(bindingType, serializedAdditionalRawData, script, udfType);
        }

        BinaryData IPersistableModel<JavaScriptFunctionRetrieveDefaultDefinitionContent>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<JavaScriptFunctionRetrieveDefaultDefinitionContent>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerStreamAnalyticsContext.Default);
                default:
                    throw new FormatException($"The model {nameof(JavaScriptFunctionRetrieveDefaultDefinitionContent)} does not support writing '{options.Format}' format.");
            }
        }

        JavaScriptFunctionRetrieveDefaultDefinitionContent IPersistableModel<JavaScriptFunctionRetrieveDefaultDefinitionContent>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<JavaScriptFunctionRetrieveDefaultDefinitionContent>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeJavaScriptFunctionRetrieveDefaultDefinitionContent(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(JavaScriptFunctionRetrieveDefaultDefinitionContent)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<JavaScriptFunctionRetrieveDefaultDefinitionContent>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
