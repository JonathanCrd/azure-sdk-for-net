// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using NUnit.Framework;

namespace Azure.ResourceManager.Sql.Samples
{
    public partial class Sample_SqlServerDnsAliasCollection
    {
        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_CreateServerDNSAlias()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ServerDnsAliasCreateOrUpdate.json
            // this example is just showing the usage of "ServerDnsAliases_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SqlServerResource created on azure
            // for more information of creating SqlServerResource, please refer to the document of SqlServerResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "Default";
            string serverName = "dns-alias-server";
            ResourceIdentifier sqlServerResourceId = SqlServerResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, serverName);
            SqlServerResource sqlServer = client.GetSqlServerResource(sqlServerResourceId);

            // get the collection of this SqlServerDnsAliasResource
            SqlServerDnsAliasCollection collection = sqlServer.GetSqlServerDnsAliases();

            // invoke the operation
            string dnsAliasName = "dns-alias-name-1";
            ArmOperation<SqlServerDnsAliasResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, dnsAliasName);
            SqlServerDnsAliasResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SqlServerDnsAliasData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_GetServerDNSAlias()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ServerDnsAliasGet.json
            // this example is just showing the usage of "ServerDnsAliases_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SqlServerResource created on azure
            // for more information of creating SqlServerResource, please refer to the document of SqlServerResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "Default";
            string serverName = "dns-alias-server";
            ResourceIdentifier sqlServerResourceId = SqlServerResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, serverName);
            SqlServerResource sqlServer = client.GetSqlServerResource(sqlServerResourceId);

            // get the collection of this SqlServerDnsAliasResource
            SqlServerDnsAliasCollection collection = sqlServer.GetSqlServerDnsAliases();

            // invoke the operation
            string dnsAliasName = "dns-alias-name-1";
            SqlServerDnsAliasResource result = await collection.GetAsync(dnsAliasName);

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SqlServerDnsAliasData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetAll_ListServerDNSAliases()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ServerDnsAliasList.json
            // this example is just showing the usage of "ServerDnsAliases_ListByServer" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SqlServerResource created on azure
            // for more information of creating SqlServerResource, please refer to the document of SqlServerResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "Default";
            string serverName = "dns-alias-server";
            ResourceIdentifier sqlServerResourceId = SqlServerResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, serverName);
            SqlServerResource sqlServer = client.GetSqlServerResource(sqlServerResourceId);

            // get the collection of this SqlServerDnsAliasResource
            SqlServerDnsAliasCollection collection = sqlServer.GetSqlServerDnsAliases();

            // invoke the operation and iterate over the result
            await foreach (SqlServerDnsAliasResource item in collection.GetAllAsync())
            {
                // the variable item is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                SqlServerDnsAliasData resourceData = item.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Exists_GetServerDNSAlias()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ServerDnsAliasGet.json
            // this example is just showing the usage of "ServerDnsAliases_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SqlServerResource created on azure
            // for more information of creating SqlServerResource, please refer to the document of SqlServerResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "Default";
            string serverName = "dns-alias-server";
            ResourceIdentifier sqlServerResourceId = SqlServerResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, serverName);
            SqlServerResource sqlServer = client.GetSqlServerResource(sqlServerResourceId);

            // get the collection of this SqlServerDnsAliasResource
            SqlServerDnsAliasCollection collection = sqlServer.GetSqlServerDnsAliases();

            // invoke the operation
            string dnsAliasName = "dns-alias-name-1";
            bool result = await collection.ExistsAsync(dnsAliasName);

            Console.WriteLine($"Succeeded: {result}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetIfExists_GetServerDNSAlias()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ServerDnsAliasGet.json
            // this example is just showing the usage of "ServerDnsAliases_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SqlServerResource created on azure
            // for more information of creating SqlServerResource, please refer to the document of SqlServerResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "Default";
            string serverName = "dns-alias-server";
            ResourceIdentifier sqlServerResourceId = SqlServerResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, serverName);
            SqlServerResource sqlServer = client.GetSqlServerResource(sqlServerResourceId);

            // get the collection of this SqlServerDnsAliasResource
            SqlServerDnsAliasCollection collection = sqlServer.GetSqlServerDnsAliases();

            // invoke the operation
            string dnsAliasName = "dns-alias-name-1";
            NullableResponse<SqlServerDnsAliasResource> response = await collection.GetIfExistsAsync(dnsAliasName);
            SqlServerDnsAliasResource result = response.HasValue ? response.Value : null;

            if (result == null)
            {
                Console.WriteLine("Succeeded with null as result");
            }
            else
            {
                // the variable result is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                SqlServerDnsAliasData resourceData = result.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }
        }
    }
}
