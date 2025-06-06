// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.Collections.Generic;
using Azure.Core;

namespace Azure.Storage.Queues
{
    internal partial class QueueGetPropertiesHeaders
    {
        private readonly Response _response;
        public QueueGetPropertiesHeaders(Response response)
        {
            _response = response;
        }
        public IDictionary<string, string> Metadata => _response.Headers.TryGetValue("x-ms-meta-", out IDictionary<string, string> value) ? value : null;
        /// <summary> The approximate number of messages in the queue. This number is not lower than the actual number of messages in the queue, but could be higher. </summary>
        public long? ApproximateMessagesCount => _response.Headers.TryGetValue("x-ms-approximate-messages-count", out long? value) ? value : null;
        /// <summary> Indicates the version of the Queue service used to execute the request. This header is returned for requests made against version 2009-09-19 and above. </summary>
        public string Version => _response.Headers.TryGetValue("x-ms-version", out string value) ? value : null;
    }
}
