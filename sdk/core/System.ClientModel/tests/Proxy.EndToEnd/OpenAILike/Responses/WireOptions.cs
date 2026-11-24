// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.ClientModel.Primitives;

namespace OpenAILike.Responses
{
    internal static class WireOptions
    {
        /// <summary>
        /// Snapshots the proxies registered in <see cref="ClientPipelineOptions.ModelProxies"/> into the
        /// <see cref="ModelReaderWriterOptions"/> a client uses on the wire, the way a generated client caches its
        /// "wire" options at construction. The client options are frozen when the client builds its pipeline, so
        /// registrations cannot be added afterwards.
        /// </summary>
        public static ModelReaderWriterOptions Create(ClientPipelineOptions pipelineOptions)
        {
            var options = new ModelReaderWriterOptions("J");
            foreach (ModelProxy proxy in pipelineOptions.ModelProxies)
            {
                options.Proxies.Add(proxy);
            }
            return options;
        }
    }
}
