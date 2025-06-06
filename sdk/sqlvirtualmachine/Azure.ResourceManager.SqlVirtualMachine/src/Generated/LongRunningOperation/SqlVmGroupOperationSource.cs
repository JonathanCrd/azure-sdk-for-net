// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.ClientModel.Primitives;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;

namespace Azure.ResourceManager.SqlVirtualMachine
{
    internal class SqlVmGroupOperationSource : IOperationSource<SqlVmGroupResource>
    {
        private readonly ArmClient _client;

        internal SqlVmGroupOperationSource(ArmClient client)
        {
            _client = client;
        }

        SqlVmGroupResource IOperationSource<SqlVmGroupResource>.CreateResult(Response response, CancellationToken cancellationToken)
        {
            var data = ModelReaderWriter.Read<SqlVmGroupData>(response.Content, ModelReaderWriterOptions.Json, AzureResourceManagerSqlVirtualMachineContext.Default);
            return new SqlVmGroupResource(_client, data);
        }

        async ValueTask<SqlVmGroupResource> IOperationSource<SqlVmGroupResource>.CreateResultAsync(Response response, CancellationToken cancellationToken)
        {
            var data = ModelReaderWriter.Read<SqlVmGroupData>(response.Content, ModelReaderWriterOptions.Json, AzureResourceManagerSqlVirtualMachineContext.Default);
            return await Task.FromResult(new SqlVmGroupResource(_client, data)).ConfigureAwait(false);
        }
    }
}
