// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.DataMigration.Models
{
    public partial class MigrateSqlServerSqlDBTaskOutputTableLevel : IUtf8JsonSerializable, IJsonModel<MigrateSqlServerSqlDBTaskOutputTableLevel>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<MigrateSqlServerSqlDBTaskOutputTableLevel>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<MigrateSqlServerSqlDBTaskOutputTableLevel>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected override void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MigrateSqlServerSqlDBTaskOutputTableLevel>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(MigrateSqlServerSqlDBTaskOutputTableLevel)} does not support writing '{format}' format.");
            }

            base.JsonModelWriteCore(writer, options);
            if (options.Format != "W" && Optional.IsDefined(ObjectName))
            {
                writer.WritePropertyName("objectName"u8);
                writer.WriteStringValue(ObjectName);
            }
            if (options.Format != "W" && Optional.IsDefined(StartedOn))
            {
                writer.WritePropertyName("startedOn"u8);
                writer.WriteStringValue(StartedOn.Value, "O");
            }
            if (options.Format != "W" && Optional.IsDefined(EndedOn))
            {
                writer.WritePropertyName("endedOn"u8);
                writer.WriteStringValue(EndedOn.Value, "O");
            }
            if (options.Format != "W" && Optional.IsDefined(State))
            {
                writer.WritePropertyName("state"u8);
                writer.WriteStringValue(State.Value.ToString());
            }
            if (options.Format != "W" && Optional.IsDefined(StatusMessage))
            {
                writer.WritePropertyName("statusMessage"u8);
                writer.WriteStringValue(StatusMessage);
            }
            if (options.Format != "W" && Optional.IsDefined(ItemsCount))
            {
                writer.WritePropertyName("itemsCount"u8);
                writer.WriteNumberValue(ItemsCount.Value);
            }
            if (options.Format != "W" && Optional.IsDefined(ItemsCompletedCount))
            {
                writer.WritePropertyName("itemsCompletedCount"u8);
                writer.WriteNumberValue(ItemsCompletedCount.Value);
            }
            if (options.Format != "W" && Optional.IsDefined(ErrorPrefix))
            {
                writer.WritePropertyName("errorPrefix"u8);
                writer.WriteStringValue(ErrorPrefix);
            }
            if (options.Format != "W" && Optional.IsDefined(ResultPrefix))
            {
                writer.WritePropertyName("resultPrefix"u8);
                writer.WriteStringValue(ResultPrefix);
            }
        }

        MigrateSqlServerSqlDBTaskOutputTableLevel IJsonModel<MigrateSqlServerSqlDBTaskOutputTableLevel>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MigrateSqlServerSqlDBTaskOutputTableLevel>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(MigrateSqlServerSqlDBTaskOutputTableLevel)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeMigrateSqlServerSqlDBTaskOutputTableLevel(document.RootElement, options);
        }

        internal static MigrateSqlServerSqlDBTaskOutputTableLevel DeserializeMigrateSqlServerSqlDBTaskOutputTableLevel(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string objectName = default;
            DateTimeOffset? startedOn = default;
            DateTimeOffset? endedOn = default;
            DataMigrationState? state = default;
            string statusMessage = default;
            long? itemsCount = default;
            long? itemsCompletedCount = default;
            string errorPrefix = default;
            string resultPrefix = default;
            string id = default;
            string resultType = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("objectName"u8))
                {
                    objectName = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("startedOn"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    startedOn = property.Value.GetDateTimeOffset("O");
                    continue;
                }
                if (property.NameEquals("endedOn"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    endedOn = property.Value.GetDateTimeOffset("O");
                    continue;
                }
                if (property.NameEquals("state"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    state = new DataMigrationState(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("statusMessage"u8))
                {
                    statusMessage = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("itemsCount"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    itemsCount = property.Value.GetInt64();
                    continue;
                }
                if (property.NameEquals("itemsCompletedCount"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    itemsCompletedCount = property.Value.GetInt64();
                    continue;
                }
                if (property.NameEquals("errorPrefix"u8))
                {
                    errorPrefix = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("resultPrefix"u8))
                {
                    resultPrefix = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("id"u8))
                {
                    id = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("resultType"u8))
                {
                    resultType = property.Value.GetString();
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new MigrateSqlServerSqlDBTaskOutputTableLevel(
                id,
                resultType,
                serializedAdditionalRawData,
                objectName,
                startedOn,
                endedOn,
                state,
                statusMessage,
                itemsCount,
                itemsCompletedCount,
                errorPrefix,
                resultPrefix);
        }

        BinaryData IPersistableModel<MigrateSqlServerSqlDBTaskOutputTableLevel>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MigrateSqlServerSqlDBTaskOutputTableLevel>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerDataMigrationContext.Default);
                default:
                    throw new FormatException($"The model {nameof(MigrateSqlServerSqlDBTaskOutputTableLevel)} does not support writing '{options.Format}' format.");
            }
        }

        MigrateSqlServerSqlDBTaskOutputTableLevel IPersistableModel<MigrateSqlServerSqlDBTaskOutputTableLevel>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MigrateSqlServerSqlDBTaskOutputTableLevel>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeMigrateSqlServerSqlDBTaskOutputTableLevel(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(MigrateSqlServerSqlDBTaskOutputTableLevel)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<MigrateSqlServerSqlDBTaskOutputTableLevel>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}
