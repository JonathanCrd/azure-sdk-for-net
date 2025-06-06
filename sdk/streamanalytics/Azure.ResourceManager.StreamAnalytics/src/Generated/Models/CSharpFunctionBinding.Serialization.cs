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
    public partial class CSharpFunctionBinding : IUtf8JsonSerializable, IJsonModel<CSharpFunctionBinding>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<CSharpFunctionBinding>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<CSharpFunctionBinding>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected override void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<CSharpFunctionBinding>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(CSharpFunctionBinding)} does not support writing '{format}' format.");
            }

            base.JsonModelWriteCore(writer, options);
            writer.WritePropertyName("properties"u8);
            writer.WriteStartObject();
            if (Optional.IsDefined(DllPath))
            {
                writer.WritePropertyName("dllPath"u8);
                writer.WriteStringValue(DllPath);
            }
            if (Optional.IsDefined(Class))
            {
                writer.WritePropertyName("class"u8);
                writer.WriteStringValue(Class);
            }
            if (Optional.IsDefined(Method))
            {
                writer.WritePropertyName("method"u8);
                writer.WriteStringValue(Method);
            }
            if (Optional.IsDefined(UpdateMode))
            {
                writer.WritePropertyName("updateMode"u8);
                writer.WriteStringValue(UpdateMode.Value.ToString());
            }
            writer.WriteEndObject();
        }

        CSharpFunctionBinding IJsonModel<CSharpFunctionBinding>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<CSharpFunctionBinding>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(CSharpFunctionBinding)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeCSharpFunctionBinding(document.RootElement, options);
        }

        internal static CSharpFunctionBinding DeserializeCSharpFunctionBinding(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string type = default;
            string dllPath = default;
            string @class = default;
            string method = default;
            StreamingJobFunctionUpdateMode? updateMode = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("type"u8))
                {
                    type = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("properties"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        property.ThrowNonNullablePropertyIsNull();
                        continue;
                    }
                    foreach (var property0 in property.Value.EnumerateObject())
                    {
                        if (property0.NameEquals("dllPath"u8))
                        {
                            dllPath = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("class"u8))
                        {
                            @class = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("method"u8))
                        {
                            method = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("updateMode"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            updateMode = new StreamingJobFunctionUpdateMode(property0.Value.GetString());
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
            return new CSharpFunctionBinding(
                type,
                serializedAdditionalRawData,
                dllPath,
                @class,
                method,
                updateMode);
        }

        BinaryData IPersistableModel<CSharpFunctionBinding>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<CSharpFunctionBinding>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerStreamAnalyticsContext.Default);
                default:
                    throw new FormatException($"The model {nameof(CSharpFunctionBinding)} does not support writing '{options.Format}' format.");
            }
        }

        CSharpFunctionBinding IPersistableModel<CSharpFunctionBinding>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<CSharpFunctionBinding>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeCSharpFunctionBinding(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(CSharpFunctionBinding)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<CSharpFunctionBinding>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
