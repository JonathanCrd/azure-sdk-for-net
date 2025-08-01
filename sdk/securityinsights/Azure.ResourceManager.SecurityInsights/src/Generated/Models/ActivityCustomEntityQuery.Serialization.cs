// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.ResourceManager.Models;

namespace Azure.ResourceManager.SecurityInsights.Models
{
    public partial class ActivityCustomEntityQuery : IUtf8JsonSerializable, IJsonModel<ActivityCustomEntityQuery>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<ActivityCustomEntityQuery>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<ActivityCustomEntityQuery>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected override void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ActivityCustomEntityQuery>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(ActivityCustomEntityQuery)} does not support writing '{format}' format.");
            }

            base.JsonModelWriteCore(writer, options);
            writer.WritePropertyName("properties"u8);
            writer.WriteStartObject();
            if (Optional.IsDefined(Title))
            {
                writer.WritePropertyName("title"u8);
                writer.WriteStringValue(Title);
            }
            if (Optional.IsDefined(Content))
            {
                writer.WritePropertyName("content"u8);
                writer.WriteStringValue(Content);
            }
            if (Optional.IsDefined(Description))
            {
                writer.WritePropertyName("description"u8);
                writer.WriteStringValue(Description);
            }
            if (Optional.IsDefined(QueryDefinitions))
            {
                writer.WritePropertyName("queryDefinitions"u8);
                writer.WriteObjectValue(QueryDefinitions, options);
            }
            if (Optional.IsDefined(InputEntityType))
            {
                writer.WritePropertyName("inputEntityType"u8);
                writer.WriteStringValue(InputEntityType.Value.ToString());
            }
            if (Optional.IsCollectionDefined(RequiredInputFieldsSets))
            {
                writer.WritePropertyName("requiredInputFieldsSets"u8);
                writer.WriteStartArray();
                foreach (var item in RequiredInputFieldsSets)
                {
                    if (item == null)
                    {
                        writer.WriteNullValue();
                        continue;
                    }
                    writer.WriteStartArray();
                    foreach (var item0 in item)
                    {
                        writer.WriteStringValue(item0);
                    }
                    writer.WriteEndArray();
                }
                writer.WriteEndArray();
            }
            if (Optional.IsCollectionDefined(EntitiesFilter))
            {
                writer.WritePropertyName("entitiesFilter"u8);
                writer.WriteStartObject();
                foreach (var item in EntitiesFilter)
                {
                    writer.WritePropertyName(item.Key);
                    if (item.Value == null)
                    {
                        writer.WriteNullValue();
                        continue;
                    }
                    writer.WriteStartArray();
                    foreach (var item0 in item.Value)
                    {
                        writer.WriteStringValue(item0);
                    }
                    writer.WriteEndArray();
                }
                writer.WriteEndObject();
            }
            if (Optional.IsDefined(TemplateName))
            {
                writer.WritePropertyName("templateName"u8);
                writer.WriteStringValue(TemplateName);
            }
            if (Optional.IsDefined(IsEnabled))
            {
                writer.WritePropertyName("enabled"u8);
                writer.WriteBooleanValue(IsEnabled.Value);
            }
            if (options.Format != "W" && Optional.IsDefined(CreatedOn))
            {
                writer.WritePropertyName("createdTimeUtc"u8);
                writer.WriteStringValue(CreatedOn.Value, "O");
            }
            if (options.Format != "W" && Optional.IsDefined(LastModifiedOn))
            {
                writer.WritePropertyName("lastModifiedTimeUtc"u8);
                writer.WriteStringValue(LastModifiedOn.Value, "O");
            }
            writer.WriteEndObject();
        }

        ActivityCustomEntityQuery IJsonModel<ActivityCustomEntityQuery>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ActivityCustomEntityQuery>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(ActivityCustomEntityQuery)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeActivityCustomEntityQuery(document.RootElement, options);
        }

        internal static ActivityCustomEntityQuery DeserializeActivityCustomEntityQuery(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            CustomEntityQueryKind kind = default;
            ETag? etag = default;
            ResourceIdentifier id = default;
            string name = default;
            ResourceType type = default;
            SystemData systemData = default;
            string title = default;
            string content = default;
            string description = default;
            ActivityEntityQueriesPropertiesQueryDefinitions queryDefinitions = default;
            SecurityInsightsEntityType? inputEntityType = default;
            IList<IList<string>> requiredInputFieldsSets = default;
            IDictionary<string, IList<string>> entitiesFilter = default;
            string templateName = default;
            bool? enabled = default;
            DateTimeOffset? createdTimeUtc = default;
            DateTimeOffset? lastModifiedTimeUtc = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("kind"u8))
                {
                    kind = new CustomEntityQueryKind(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("etag"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    etag = new ETag(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("id"u8))
                {
                    id = new ResourceIdentifier(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("name"u8))
                {
                    name = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("type"u8))
                {
                    type = new ResourceType(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("systemData"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    systemData = ModelReaderWriter.Read<SystemData>(new BinaryData(Encoding.UTF8.GetBytes(property.Value.GetRawText())), ModelSerializationExtensions.WireOptions, AzureResourceManagerSecurityInsightsContext.Default);
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
                        if (property0.NameEquals("title"u8))
                        {
                            title = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("content"u8))
                        {
                            content = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("description"u8))
                        {
                            description = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("queryDefinitions"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            queryDefinitions = ActivityEntityQueriesPropertiesQueryDefinitions.DeserializeActivityEntityQueriesPropertiesQueryDefinitions(property0.Value, options);
                            continue;
                        }
                        if (property0.NameEquals("inputEntityType"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            inputEntityType = new SecurityInsightsEntityType(property0.Value.GetString());
                            continue;
                        }
                        if (property0.NameEquals("requiredInputFieldsSets"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            List<IList<string>> array = new List<IList<string>>();
                            foreach (var item in property0.Value.EnumerateArray())
                            {
                                if (item.ValueKind == JsonValueKind.Null)
                                {
                                    array.Add(null);
                                }
                                else
                                {
                                    List<string> array0 = new List<string>();
                                    foreach (var item0 in item.EnumerateArray())
                                    {
                                        array0.Add(item0.GetString());
                                    }
                                    array.Add(array0);
                                }
                            }
                            requiredInputFieldsSets = array;
                            continue;
                        }
                        if (property0.NameEquals("entitiesFilter"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            Dictionary<string, IList<string>> dictionary = new Dictionary<string, IList<string>>();
                            foreach (var property1 in property0.Value.EnumerateObject())
                            {
                                if (property1.Value.ValueKind == JsonValueKind.Null)
                                {
                                    dictionary.Add(property1.Name, null);
                                }
                                else
                                {
                                    List<string> array = new List<string>();
                                    foreach (var item in property1.Value.EnumerateArray())
                                    {
                                        array.Add(item.GetString());
                                    }
                                    dictionary.Add(property1.Name, array);
                                }
                            }
                            entitiesFilter = dictionary;
                            continue;
                        }
                        if (property0.NameEquals("templateName"u8))
                        {
                            templateName = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("enabled"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            enabled = property0.Value.GetBoolean();
                            continue;
                        }
                        if (property0.NameEquals("createdTimeUtc"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            createdTimeUtc = property0.Value.GetDateTimeOffset("O");
                            continue;
                        }
                        if (property0.NameEquals("lastModifiedTimeUtc"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            lastModifiedTimeUtc = property0.Value.GetDateTimeOffset("O");
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
            return new ActivityCustomEntityQuery(
                id,
                name,
                type,
                systemData,
                kind,
                etag,
                serializedAdditionalRawData,
                title,
                content,
                description,
                queryDefinitions,
                inputEntityType,
                requiredInputFieldsSets ?? new ChangeTrackingList<IList<string>>(),
                entitiesFilter ?? new ChangeTrackingDictionary<string, IList<string>>(),
                templateName,
                enabled,
                createdTimeUtc,
                lastModifiedTimeUtc);
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

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(Name), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  name: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(Name))
                {
                    builder.Append("  name: ");
                    if (Name.Contains(Environment.NewLine))
                    {
                        builder.AppendLine("'''");
                        builder.AppendLine($"{Name}'''");
                    }
                    else
                    {
                        builder.AppendLine($"'{Name}'");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(Kind), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  kind: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                builder.Append("  kind: ");
                builder.AppendLine($"'{Kind.ToString()}'");
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(ETag), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  etag: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(ETag))
                {
                    builder.Append("  etag: ");
                    builder.AppendLine($"'{ETag.Value.ToString()}'");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(Id), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  id: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(Id))
                {
                    builder.Append("  id: ");
                    builder.AppendLine($"'{Id.ToString()}'");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(SystemData), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  systemData: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(SystemData))
                {
                    builder.Append("  systemData: ");
                    builder.AppendLine($"'{SystemData.ToString()}'");
                }
            }

            builder.Append("  properties:");
            builder.AppendLine(" {");
            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(Title), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    title: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(Title))
                {
                    builder.Append("    title: ");
                    if (Title.Contains(Environment.NewLine))
                    {
                        builder.AppendLine("'''");
                        builder.AppendLine($"{Title}'''");
                    }
                    else
                    {
                        builder.AppendLine($"'{Title}'");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(Content), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    content: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(Content))
                {
                    builder.Append("    content: ");
                    if (Content.Contains(Environment.NewLine))
                    {
                        builder.AppendLine("'''");
                        builder.AppendLine($"{Content}'''");
                    }
                    else
                    {
                        builder.AppendLine($"'{Content}'");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(Description), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    description: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(Description))
                {
                    builder.Append("    description: ");
                    if (Description.Contains(Environment.NewLine))
                    {
                        builder.AppendLine("'''");
                        builder.AppendLine($"{Description}'''");
                    }
                    else
                    {
                        builder.AppendLine($"'{Description}'");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue("Query", out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    queryDefinitions: ");
                builder.AppendLine("{");
                builder.AppendLine("      queryDefinitions: {");
                builder.Append("        query: ");
                builder.AppendLine(propertyOverride);
                builder.AppendLine("      }");
                builder.AppendLine("    }");
            }
            else
            {
                if (Optional.IsDefined(QueryDefinitions))
                {
                    builder.Append("    queryDefinitions: ");
                    BicepSerializationHelpers.AppendChildObject(builder, QueryDefinitions, options, 4, false, "    queryDefinitions: ");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(InputEntityType), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    inputEntityType: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(InputEntityType))
                {
                    builder.Append("    inputEntityType: ");
                    builder.AppendLine($"'{InputEntityType.Value.ToString()}'");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(RequiredInputFieldsSets), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    requiredInputFieldsSets: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsCollectionDefined(RequiredInputFieldsSets))
                {
                    if (RequiredInputFieldsSets.Any())
                    {
                        builder.Append("    requiredInputFieldsSets: ");
                        builder.AppendLine("[");
                        foreach (var item in RequiredInputFieldsSets)
                        {
                            if (item == null)
                            {
                                builder.Append("null");
                                continue;
                            }
                            builder.AppendLine("[");
                            foreach (var item0 in item)
                            {
                                if (item0 == null)
                                {
                                    builder.Append("null");
                                    continue;
                                }
                                if (item0.Contains(Environment.NewLine))
                                {
                                    builder.AppendLine("      '''");
                                    builder.AppendLine($"{item0}'''");
                                }
                                else
                                {
                                    builder.AppendLine($"      '{item0}'");
                                }
                            }
                            builder.AppendLine("    ]");
                        }
                        builder.AppendLine("    ]");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(EntitiesFilter), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    entitiesFilter: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsCollectionDefined(EntitiesFilter))
                {
                    if (EntitiesFilter.Any())
                    {
                        builder.Append("    entitiesFilter: ");
                        builder.AppendLine("{");
                        foreach (var item in EntitiesFilter)
                        {
                            builder.Append($"        '{item.Key}': ");
                            if (item.Value == null)
                            {
                                builder.Append("null");
                                continue;
                            }
                            builder.AppendLine("[");
                            foreach (var item0 in item.Value)
                            {
                                if (item0 == null)
                                {
                                    builder.Append("null");
                                    continue;
                                }
                                if (item0.Contains(Environment.NewLine))
                                {
                                    builder.AppendLine("        '''");
                                    builder.AppendLine($"{item0}'''");
                                }
                                else
                                {
                                    builder.AppendLine($"        '{item0}'");
                                }
                            }
                            builder.AppendLine("      ]");
                        }
                        builder.AppendLine("    }");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(TemplateName), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    templateName: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(TemplateName))
                {
                    builder.Append("    templateName: ");
                    if (TemplateName.Contains(Environment.NewLine))
                    {
                        builder.AppendLine("'''");
                        builder.AppendLine($"{TemplateName}'''");
                    }
                    else
                    {
                        builder.AppendLine($"'{TemplateName}'");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(IsEnabled), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    enabled: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(IsEnabled))
                {
                    builder.Append("    enabled: ");
                    var boolValue = IsEnabled.Value == true ? "true" : "false";
                    builder.AppendLine($"{boolValue}");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(CreatedOn), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    createdTimeUtc: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(CreatedOn))
                {
                    builder.Append("    createdTimeUtc: ");
                    var formattedDateTimeString = TypeFormatters.ToString(CreatedOn.Value, "o");
                    builder.AppendLine($"'{formattedDateTimeString}'");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(LastModifiedOn), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    lastModifiedTimeUtc: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(LastModifiedOn))
                {
                    builder.Append("    lastModifiedTimeUtc: ");
                    var formattedDateTimeString = TypeFormatters.ToString(LastModifiedOn.Value, "o");
                    builder.AppendLine($"'{formattedDateTimeString}'");
                }
            }

            builder.AppendLine("  }");
            builder.AppendLine("}");
            return BinaryData.FromString(builder.ToString());
        }

        BinaryData IPersistableModel<ActivityCustomEntityQuery>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ActivityCustomEntityQuery>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerSecurityInsightsContext.Default);
                case "bicep":
                    return SerializeBicep(options);
                default:
                    throw new FormatException($"The model {nameof(ActivityCustomEntityQuery)} does not support writing '{options.Format}' format.");
            }
        }

        ActivityCustomEntityQuery IPersistableModel<ActivityCustomEntityQuery>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ActivityCustomEntityQuery>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeActivityCustomEntityQuery(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(ActivityCustomEntityQuery)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<ActivityCustomEntityQuery>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
