// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Text.Json;
using Azure.ResourceManager.Hci.Models;

namespace Azure.ResourceManager.Hci
{
    public partial class HciEdgeDeviceResource : IJsonModel<HciEdgeDeviceData>
    {
        private static UnknownEdgeDevice s_dataDeserializationInstance;
        private static UnknownEdgeDevice DataDeserializationInstance => s_dataDeserializationInstance ??= new();

        void IJsonModel<HciEdgeDeviceData>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options) => ((IJsonModel<HciEdgeDeviceData>)Data).Write(writer, options);

        HciEdgeDeviceData IJsonModel<HciEdgeDeviceData>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options) => ((IJsonModel<HciEdgeDeviceData>)DataDeserializationInstance).Create(ref reader, options);

        BinaryData IPersistableModel<HciEdgeDeviceData>.Write(ModelReaderWriterOptions options) => ModelReaderWriter.Write<HciEdgeDeviceData>(Data, options, AzureResourceManagerHciContext.Default);

        HciEdgeDeviceData IPersistableModel<HciEdgeDeviceData>.Create(BinaryData data, ModelReaderWriterOptions options) => ModelReaderWriter.Read<HciEdgeDeviceData>(data, options, AzureResourceManagerHciContext.Default);

        string IPersistableModel<HciEdgeDeviceData>.GetFormatFromOptions(ModelReaderWriterOptions options) => ((IPersistableModel<HciEdgeDeviceData>)DataDeserializationInstance).GetFormatFromOptions(options);
    }
}
