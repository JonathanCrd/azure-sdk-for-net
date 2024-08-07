// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.Network.Models
{
    public partial class FirewallPacketCaptureContent : IUtf8JsonSerializable, IJsonModel<FirewallPacketCaptureContent>
    {
        /// <summary>
        /// Dummy implementation.
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        FirewallPacketCaptureContent IJsonModel<FirewallPacketCaptureContent>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Dummy implementation.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        FirewallPacketCaptureContent IPersistableModel<FirewallPacketCaptureContent>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Dummy implementation.
        /// </summary>
        /// <param name="options"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        string IPersistableModel<FirewallPacketCaptureContent>.GetFormatFromOptions(ModelReaderWriterOptions options)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Dummy implementation.
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="options"></param>
        /// <exception cref="NotImplementedException"></exception>
        void IJsonModel<FirewallPacketCaptureContent>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Dummy implementation.
        /// </summary>
        /// <param name="options"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        BinaryData IPersistableModel<FirewallPacketCaptureContent>.Write(ModelReaderWriterOptions options)
        {
            throw new NotImplementedException();
        }
    }
}
