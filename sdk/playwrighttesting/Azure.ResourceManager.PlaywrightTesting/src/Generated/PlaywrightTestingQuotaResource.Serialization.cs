// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Text.Json;

namespace Azure.ResourceManager.PlaywrightTesting
{
    public partial class PlaywrightTestingQuotaResource : IJsonModel<PlaywrightTestingQuotaData>
    {
        private static PlaywrightTestingQuotaData s_dataDeserializationInstance;
        private static PlaywrightTestingQuotaData DataDeserializationInstance => s_dataDeserializationInstance ??= new();

        void IJsonModel<PlaywrightTestingQuotaData>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options) => ((IJsonModel<PlaywrightTestingQuotaData>)Data).Write(writer, options);

        PlaywrightTestingQuotaData IJsonModel<PlaywrightTestingQuotaData>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options) => ((IJsonModel<PlaywrightTestingQuotaData>)DataDeserializationInstance).Create(ref reader, options);

        BinaryData IPersistableModel<PlaywrightTestingQuotaData>.Write(ModelReaderWriterOptions options) => ModelReaderWriter.Write<PlaywrightTestingQuotaData>(Data, options, AzureResourceManagerPlaywrightTestingContext.Default);

        PlaywrightTestingQuotaData IPersistableModel<PlaywrightTestingQuotaData>.Create(BinaryData data, ModelReaderWriterOptions options) => ModelReaderWriter.Read<PlaywrightTestingQuotaData>(data, options, AzureResourceManagerPlaywrightTestingContext.Default);

        string IPersistableModel<PlaywrightTestingQuotaData>.GetFormatFromOptions(ModelReaderWriterOptions options) => ((IPersistableModel<PlaywrightTestingQuotaData>)DataDeserializationInstance).GetFormatFromOptions(options);
    }
}
