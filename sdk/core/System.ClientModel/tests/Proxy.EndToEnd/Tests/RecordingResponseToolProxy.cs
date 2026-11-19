// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.ClientModel.Primitives;
using System.Text.Json;
using System.Threading;
using OpenAILike.Responses;

namespace Proxy.EndToEnd.Tests
{
    /// <summary>
    /// Test-only decorator that forwards every call to a library proxy and counts the reads and writes the library
    /// proxy performed. Selection stays with the wrapped proxy's <c>CanHandle</c> methods, so the counts show which
    /// models and payloads that proxy actually took over.
    /// </summary>
    internal sealed class RecordingResponseToolProxy : ModelProxy<ResponseTool>, IJsonModel<ResponseTool>
    {
        private readonly ModelProxy<ResponseTool> _inner;
        private int _reads;
        private int _writes;

        public RecordingResponseToolProxy(ModelProxy<ResponseTool> inner)
        {
            _inner = inner;
        }

        public int Reads => Volatile.Read(ref _reads);

        public int Writes => Volatile.Read(ref _writes);

        public override bool CanHandle(ResponseTool model, ModelReaderWriterOptions options)
            => _inner.CanHandle(model, options);

        public override bool CanHandle(ReadOnlyMemory<byte> data, ModelReaderWriterOptions options)
            => _inner.CanHandle(data, options);

        public override bool CanHandle(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
            => _inner.CanHandle(ref reader, options);

        void IJsonModel<ResponseTool>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            Interlocked.Increment(ref _writes);
            ((IJsonModel<ResponseTool>)_inner).Write(writer, options);
        }

        ResponseTool? IJsonModel<ResponseTool>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            Interlocked.Increment(ref _reads);
            return ((IJsonModel<ResponseTool>)_inner).Create(ref reader, options);
        }

        public override BinaryData Write(ModelReaderWriterOptions options)
        {
            Interlocked.Increment(ref _writes);
            return _inner.Write(options);
        }

        public override ResponseTool Create(BinaryData data, ModelReaderWriterOptions options)
        {
            Interlocked.Increment(ref _reads);
            return _inner.Create(data, options);
        }

        public override string GetFormatFromOptions(ModelReaderWriterOptions options)
            => _inner.GetFormatFromOptions(options);
    }
}
