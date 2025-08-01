// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Data.SchemaRegistry.Models;

namespace Azure.Data.SchemaRegistry
{
    internal partial class SchemaRegistryClientGetSchemaVersionsCollectionResult : Pageable<BinaryData>
    {
        private readonly SchemaRegistryClient _client;
        private readonly string _groupName;
        private readonly string _schemaName;
        private readonly RequestContext _context;

        /// <summary> Initializes a new instance of SchemaRegistryClientGetSchemaVersionsCollectionResult, which is used to iterate over the pages of a collection. </summary>
        /// <param name="client"> The SchemaRegistryClient client used to send requests. </param>
        /// <param name="groupName"> Name of schema group. </param>
        /// <param name="schemaName"> Name of schema. </param>
        /// <param name="context"> The request options, which can override default behaviors of the client pipeline on a per-call basis. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="groupName"/> or <paramref name="schemaName"/> is null. </exception>
        /// <exception cref="ArgumentException"> <paramref name="groupName"/> or <paramref name="schemaName"/> is an empty string, and was expected to be non-empty. </exception>
        public SchemaRegistryClientGetSchemaVersionsCollectionResult(SchemaRegistryClient client, string groupName, string schemaName, RequestContext context) : base(context?.CancellationToken ?? default)
        {
            Argument.AssertNotNullOrEmpty(groupName, nameof(groupName));
            Argument.AssertNotNullOrEmpty(schemaName, nameof(schemaName));

            _client = client;
            _groupName = groupName;
            _schemaName = schemaName;
            _context = context;
        }

        /// <summary> Gets the pages of SchemaRegistryClientGetSchemaVersionsCollectionResult as an enumerable collection. </summary>
        /// <param name="continuationToken"> A continuation token indicating where to resume paging. </param>
        /// <param name="pageSizeHint"> The number of items per page. </param>
        /// <returns> The pages of SchemaRegistryClientGetSchemaVersionsCollectionResult as an enumerable collection. </returns>
        public override IEnumerable<Page<BinaryData>> AsPages(string continuationToken, int? pageSizeHint)
        {
            Uri nextPage = continuationToken != null ? new Uri(continuationToken) : null;
            do
            {
                Response response = GetNextResponse(pageSizeHint, nextPage);
                if (response is null)
                {
                    yield break;
                }
                SchemaVersions responseWithType = (SchemaVersions)response;
                List<BinaryData> items = new List<BinaryData>();
                foreach (var item in responseWithType.Value)
                {
                    items.Add(BinaryData.FromObjectAsJson(item));
                }
                nextPage = responseWithType.NextLink;
                yield return Page<BinaryData>.FromValues(items, nextPage?.AbsoluteUri, response);
            }
            while (nextPage != null);
        }

        /// <summary> Get next page. </summary>
        /// <param name="pageSizeHint"> The number of items per page. </param>
        /// <param name="nextLink"> The next link to use for the next page of results. </param>
        private Response GetNextResponse(int? pageSizeHint, Uri nextLink)
        {
            HttpMessage message = nextLink != null ? _client.CreateNextGetSchemaVersionsRequest(nextLink, _groupName, _schemaName, _context) : _client.CreateGetSchemaVersionsRequest(_groupName, _schemaName, _context);
            using DiagnosticScope scope = _client.ClientDiagnostics.CreateScope("SchemaRegistryClient.GetSchemaVersions");
            scope.Start();
            try
            {
                return _client.Pipeline.ProcessMessage(message, _context);
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }
    }
}
