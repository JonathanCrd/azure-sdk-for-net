// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Text.Json;

namespace Azure.ResourceManager.NetworkCloud
{
    public partial class NetworkCloudCloudServicesNetworkResource : IJsonModel<NetworkCloudCloudServicesNetworkData>
    {
        private static NetworkCloudCloudServicesNetworkData s_dataDeserializationInstance;
        private static NetworkCloudCloudServicesNetworkData DataDeserializationInstance => s_dataDeserializationInstance ??= new();

        void IJsonModel<NetworkCloudCloudServicesNetworkData>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options) => ((IJsonModel<NetworkCloudCloudServicesNetworkData>)Data).Write(writer, options);

        NetworkCloudCloudServicesNetworkData IJsonModel<NetworkCloudCloudServicesNetworkData>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options) => ((IJsonModel<NetworkCloudCloudServicesNetworkData>)DataDeserializationInstance).Create(ref reader, options);

        BinaryData IPersistableModel<NetworkCloudCloudServicesNetworkData>.Write(ModelReaderWriterOptions options) => ModelReaderWriter.Write<NetworkCloudCloudServicesNetworkData>(Data, options, AzureResourceManagerNetworkCloudContext.Default);

        NetworkCloudCloudServicesNetworkData IPersistableModel<NetworkCloudCloudServicesNetworkData>.Create(BinaryData data, ModelReaderWriterOptions options) => ModelReaderWriter.Read<NetworkCloudCloudServicesNetworkData>(data, options, AzureResourceManagerNetworkCloudContext.Default);

        string IPersistableModel<NetworkCloudCloudServicesNetworkData>.GetFormatFromOptions(ModelReaderWriterOptions options) => ((IPersistableModel<NetworkCloudCloudServicesNetworkData>)DataDeserializationInstance).GetFormatFromOptions(options);
    }
}
