// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.Media.VideoAnalyzer.Edge.Models
{
    public partial class PipelineTopologyProperties : IUtf8JsonSerializable
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            if (Optional.IsDefined(Description))
            {
                writer.WritePropertyName("description"u8);
                writer.WriteStringValue(Description);
            }
            if (Optional.IsCollectionDefined(Parameters))
            {
                writer.WritePropertyName("parameters"u8);
                writer.WriteStartArray();
                foreach (var item in Parameters)
                {
                    writer.WriteObjectValue(item);
                }
                writer.WriteEndArray();
            }
            if (Optional.IsCollectionDefined(Sources))
            {
                writer.WritePropertyName("sources"u8);
                writer.WriteStartArray();
                foreach (var item in Sources)
                {
                    writer.WriteObjectValue(item);
                }
                writer.WriteEndArray();
            }
            if (Optional.IsCollectionDefined(Processors))
            {
                writer.WritePropertyName("processors"u8);
                writer.WriteStartArray();
                foreach (var item in Processors)
                {
                    writer.WriteObjectValue(item);
                }
                writer.WriteEndArray();
            }
            if (Optional.IsCollectionDefined(Sinks))
            {
                writer.WritePropertyName("sinks"u8);
                writer.WriteStartArray();
                foreach (var item in Sinks)
                {
                    writer.WriteObjectValue(item);
                }
                writer.WriteEndArray();
            }
            writer.WriteEndObject();
        }

        internal static PipelineTopologyProperties DeserializePipelineTopologyProperties(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string description = default;
            IList<ParameterDeclaration> parameters = default;
            IList<SourceNodeBase> sources = default;
            IList<ProcessorNodeBase> processors = default;
            IList<SinkNodeBase> sinks = default;
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("description"u8))
                {
                    description = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("parameters"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    List<ParameterDeclaration> array = new List<ParameterDeclaration>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(ParameterDeclaration.DeserializeParameterDeclaration(item));
                    }
                    parameters = array;
                    continue;
                }
                if (property.NameEquals("sources"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    List<SourceNodeBase> array = new List<SourceNodeBase>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(SourceNodeBase.DeserializeSourceNodeBase(item));
                    }
                    sources = array;
                    continue;
                }
                if (property.NameEquals("processors"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    List<ProcessorNodeBase> array = new List<ProcessorNodeBase>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(ProcessorNodeBase.DeserializeProcessorNodeBase(item));
                    }
                    processors = array;
                    continue;
                }
                if (property.NameEquals("sinks"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    List<SinkNodeBase> array = new List<SinkNodeBase>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        array.Add(SinkNodeBase.DeserializeSinkNodeBase(item));
                    }
                    sinks = array;
                    continue;
                }
            }
            return new PipelineTopologyProperties(description, parameters ?? new ChangeTrackingList<ParameterDeclaration>(), sources ?? new ChangeTrackingList<SourceNodeBase>(), processors ?? new ChangeTrackingList<ProcessorNodeBase>(), sinks ?? new ChangeTrackingList<SinkNodeBase>());
        }

        /// <summary> Deserializes the model from a raw response. </summary>
        /// <param name="response"> The response to deserialize the model from. </param>
        internal static PipelineTopologyProperties FromResponse(Response response)
        {
            using var document = JsonDocument.Parse(response.Content, ModelSerializationExtensions.JsonDocumentOptions);
            return DeserializePipelineTopologyProperties(document.RootElement);
        }

        /// <summary> Convert into a <see cref="RequestContent"/>. </summary>
        internal virtual RequestContent ToRequestContent()
        {
            var content = new Utf8JsonRequestContent();
            content.JsonWriter.WriteObjectValue(this);
            return content;
        }
    }
}
