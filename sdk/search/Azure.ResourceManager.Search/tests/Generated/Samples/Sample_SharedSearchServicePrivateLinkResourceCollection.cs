// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager.Search.Models;
using NUnit.Framework;

namespace Azure.ResourceManager.Search.Samples
{
    public partial class Sample_SharedSearchServicePrivateLinkResourceCollection
    {
        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_SharedPrivateLinkResourceCreateOrUpdate()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/CreateOrUpdateSharedPrivateLinkResource.json
            // this example is just showing the usage of "SharedPrivateLinkResources_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SearchServiceResource created on azure
            // for more information of creating SearchServiceResource, please refer to the document of SearchServiceResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            string searchServiceName = "mysearchservice";
            ResourceIdentifier searchServiceResourceId = SearchServiceResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, searchServiceName);
            SearchServiceResource searchService = client.GetSearchServiceResource(searchServiceResourceId);

            // get the collection of this SharedSearchServicePrivateLinkResource
            SharedSearchServicePrivateLinkResourceCollection collection = searchService.GetSharedSearchServicePrivateLinkResources();

            // invoke the operation
            string sharedPrivateLinkResourceName = "testResource";
            SharedSearchServicePrivateLinkResourceData data = new SharedSearchServicePrivateLinkResourceData
            {
                Properties = new SharedSearchServicePrivateLinkResourceProperties
                {
                    PrivateLinkResourceId = new ResourceIdentifier("/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storageAccountName"),
                    GroupId = "blob",
                    RequestMessage = "please approve",
                    ResourceRegion = default,
                },
            };
            ArmOperation<SharedSearchServicePrivateLinkResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, sharedPrivateLinkResourceName, data);
            SharedSearchServicePrivateLinkResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SharedSearchServicePrivateLinkResourceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_SharedPrivateLinkResourceGet()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/GetSharedPrivateLinkResource.json
            // this example is just showing the usage of "SharedPrivateLinkResources_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SearchServiceResource created on azure
            // for more information of creating SearchServiceResource, please refer to the document of SearchServiceResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            string searchServiceName = "mysearchservice";
            ResourceIdentifier searchServiceResourceId = SearchServiceResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, searchServiceName);
            SearchServiceResource searchService = client.GetSearchServiceResource(searchServiceResourceId);

            // get the collection of this SharedSearchServicePrivateLinkResource
            SharedSearchServicePrivateLinkResourceCollection collection = searchService.GetSharedSearchServicePrivateLinkResources();

            // invoke the operation
            string sharedPrivateLinkResourceName = "testResource";
            SharedSearchServicePrivateLinkResource result = await collection.GetAsync(sharedPrivateLinkResourceName);

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SharedSearchServicePrivateLinkResourceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetAll_ListSharedPrivateLinkResourcesByService()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/ListSharedPrivateLinkResourcesByService.json
            // this example is just showing the usage of "SharedPrivateLinkResources_ListByService" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SearchServiceResource created on azure
            // for more information of creating SearchServiceResource, please refer to the document of SearchServiceResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            string searchServiceName = "mysearchservice";
            ResourceIdentifier searchServiceResourceId = SearchServiceResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, searchServiceName);
            SearchServiceResource searchService = client.GetSearchServiceResource(searchServiceResourceId);

            // get the collection of this SharedSearchServicePrivateLinkResource
            SharedSearchServicePrivateLinkResourceCollection collection = searchService.GetSharedSearchServicePrivateLinkResources();

            // invoke the operation and iterate over the result
            await foreach (SharedSearchServicePrivateLinkResource item in collection.GetAllAsync())
            {
                // the variable item is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                SharedSearchServicePrivateLinkResourceData resourceData = item.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Exists_SharedPrivateLinkResourceGet()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/GetSharedPrivateLinkResource.json
            // this example is just showing the usage of "SharedPrivateLinkResources_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SearchServiceResource created on azure
            // for more information of creating SearchServiceResource, please refer to the document of SearchServiceResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            string searchServiceName = "mysearchservice";
            ResourceIdentifier searchServiceResourceId = SearchServiceResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, searchServiceName);
            SearchServiceResource searchService = client.GetSearchServiceResource(searchServiceResourceId);

            // get the collection of this SharedSearchServicePrivateLinkResource
            SharedSearchServicePrivateLinkResourceCollection collection = searchService.GetSharedSearchServicePrivateLinkResources();

            // invoke the operation
            string sharedPrivateLinkResourceName = "testResource";
            bool result = await collection.ExistsAsync(sharedPrivateLinkResourceName);

            Console.WriteLine($"Succeeded: {result}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetIfExists_SharedPrivateLinkResourceGet()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/GetSharedPrivateLinkResource.json
            // this example is just showing the usage of "SharedPrivateLinkResources_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SearchServiceResource created on azure
            // for more information of creating SearchServiceResource, please refer to the document of SearchServiceResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            string searchServiceName = "mysearchservice";
            ResourceIdentifier searchServiceResourceId = SearchServiceResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, searchServiceName);
            SearchServiceResource searchService = client.GetSearchServiceResource(searchServiceResourceId);

            // get the collection of this SharedSearchServicePrivateLinkResource
            SharedSearchServicePrivateLinkResourceCollection collection = searchService.GetSharedSearchServicePrivateLinkResources();

            // invoke the operation
            string sharedPrivateLinkResourceName = "testResource";
            NullableResponse<SharedSearchServicePrivateLinkResource> response = await collection.GetIfExistsAsync(sharedPrivateLinkResourceName);
            SharedSearchServicePrivateLinkResource result = response.HasValue ? response.Value : null;

            if (result == null)
            {
                Console.WriteLine("Succeeded with null as result");
            }
            else
            {
                // the variable result is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                SharedSearchServicePrivateLinkResourceData resourceData = result.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }
        }
    }
}
