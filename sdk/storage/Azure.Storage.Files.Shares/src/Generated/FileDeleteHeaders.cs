// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using Azure.Core;

namespace Azure.Storage.Files.Shares
{
    internal partial class FileDeleteHeaders
    {
        private readonly Response _response;
        public FileDeleteHeaders(Response response)
        {
            _response = response;
        }
        /// <summary> Indicates the version of the File service used to execute the request. </summary>
        public string Version => _response.Headers.TryGetValue("x-ms-version", out string value) ? value : null;
        /// <summary> NFS only. The link count of the file or directory. </summary>
        public long? LinkCount => _response.Headers.TryGetValue("x-ms-link-count", out long? value) ? value : null;
    }
}
