// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager.Models;
using Azure.ResourceManager.Resources;
using Azure.ResourceManager.Search.Models;
using NUnit.Framework;

namespace Azure.ResourceManager.Search.Samples
{
    public partial class Sample_SearchServiceCollection
    {
        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_SearchCreateOrUpdateService()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchCreateOrUpdateService.json
            // this example is just showing the usage of "Services_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            SearchServiceData data = new SearchServiceData(new AzureLocation("westus"))
            {
                SearchSkuName = SearchServiceSkuName.Standard,
                ReplicaCount = 3,
                PartitionCount = 1,
                HostingMode = SearchServiceHostingMode.Default,
                ComputeType = SearchServiceComputeType.Default,
                Tags =
{
["app-name"] = "My e-commerce app"
},
            };
            ArmOperation<SearchServiceResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, searchServiceName, data);
            SearchServiceResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SearchServiceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_SearchCreateOrUpdateServiceAuthOptions()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchCreateOrUpdateServiceAuthOptions.json
            // this example is just showing the usage of "Services_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            SearchServiceData data = new SearchServiceData(new AzureLocation("westus"))
            {
                SearchSkuName = SearchServiceSkuName.Standard,
                ReplicaCount = 3,
                PartitionCount = 1,
                HostingMode = SearchServiceHostingMode.Default,
                ComputeType = SearchServiceComputeType.Default,
                AuthOptions = new SearchAadAuthDataPlaneAuthOptions
                {
                    AadAuthFailureMode = SearchAadAuthFailureMode.Http401WithBearerChallenge,
                },
                Tags =
{
["app-name"] = "My e-commerce app"
},
            };
            ArmOperation<SearchServiceResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, searchServiceName, data);
            SearchServiceResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SearchServiceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_SearchCreateOrUpdateServiceDisableLocalAuth()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchCreateOrUpdateServiceDisableLocalAuth.json
            // this example is just showing the usage of "Services_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            SearchServiceData data = new SearchServiceData(new AzureLocation("westus"))
            {
                SearchSkuName = SearchServiceSkuName.Standard,
                ReplicaCount = 3,
                PartitionCount = 1,
                HostingMode = SearchServiceHostingMode.Default,
                ComputeType = SearchServiceComputeType.Default,
                IsLocalAuthDisabled = true,
                Tags =
{
["app-name"] = "My e-commerce app"
},
            };
            ArmOperation<SearchServiceResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, searchServiceName, data);
            SearchServiceResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SearchServiceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_SearchCreateOrUpdateServiceToAllowAccessFromPrivateEndpoints()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchCreateOrUpdateServiceToAllowAccessFromPrivateEndpoints.json
            // this example is just showing the usage of "Services_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            SearchServiceData data = new SearchServiceData(new AzureLocation("westus"))
            {
                SearchSkuName = SearchServiceSkuName.Standard,
                ReplicaCount = 3,
                PartitionCount = 1,
                HostingMode = SearchServiceHostingMode.Default,
                ComputeType = SearchServiceComputeType.Default,
                PublicInternetAccess = SearchServicePublicInternetAccess.Disabled,
                Tags =
{
["app-name"] = "My e-commerce app"
},
            };
            ArmOperation<SearchServiceResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, searchServiceName, data);
            SearchServiceResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SearchServiceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_SearchCreateOrUpdateServiceToAllowAccessFromPublicCustomIPs()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchCreateOrUpdateServiceToAllowAccessFromPublicCustomIPs.json
            // this example is just showing the usage of "Services_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            SearchServiceData data = new SearchServiceData(new AzureLocation("westus"))
            {
                SearchSkuName = SearchServiceSkuName.Standard,
                ReplicaCount = 1,
                PartitionCount = 1,
                HostingMode = SearchServiceHostingMode.Default,
                ComputeType = SearchServiceComputeType.Default,
                NetworkRuleSet = new SearchServiceNetworkRuleSet
                {
                    IPRules = {new SearchServiceIPRule
{
Value = "123.4.5.6",
}, new SearchServiceIPRule
{
Value = "123.4.6.0/18",
}},
                },
                Tags =
{
["app-name"] = "My e-commerce app"
},
            };
            ArmOperation<SearchServiceResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, searchServiceName, data);
            SearchServiceResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SearchServiceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_SearchCreateOrUpdateServiceToAllowAccessFromPublicCustomIPsAndBypass()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchCreateOrUpdateServiceToAllowAccessFromPublicCustomIPsAndBypass.json
            // this example is just showing the usage of "Services_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            SearchServiceData data = new SearchServiceData(new AzureLocation("westus"))
            {
                SearchSkuName = SearchServiceSkuName.Standard,
                ReplicaCount = 1,
                PartitionCount = 1,
                HostingMode = SearchServiceHostingMode.Default,
                ComputeType = SearchServiceComputeType.Default,
                NetworkRuleSet = new SearchServiceNetworkRuleSet
                {
                    IPRules = {new SearchServiceIPRule
{
Value = "123.4.5.6",
}, new SearchServiceIPRule
{
Value = "123.4.6.0/18",
}},
                    Bypass = SearchBypass.AzureServices,
                },
                Tags =
{
["app-name"] = "My e-commerce app"
},
            };
            ArmOperation<SearchServiceResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, searchServiceName, data);
            SearchServiceResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SearchServiceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_SearchCreateOrUpdateServiceWithCmkEnforcement()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchCreateOrUpdateServiceWithCmkEnforcement.json
            // this example is just showing the usage of "Services_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            SearchServiceData data = new SearchServiceData(new AzureLocation("westus"))
            {
                SearchSkuName = SearchServiceSkuName.Standard,
                ReplicaCount = 3,
                PartitionCount = 1,
                HostingMode = SearchServiceHostingMode.Default,
                ComputeType = SearchServiceComputeType.Default,
                EncryptionWithCmk = new SearchEncryptionWithCmk
                {
                    Enforcement = SearchEncryptionWithCmkEnforcement.Enabled,
                },
                Tags =
{
["app-name"] = "My e-commerce app"
},
            };
            ArmOperation<SearchServiceResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, searchServiceName, data);
            SearchServiceResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SearchServiceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_SearchCreateOrUpdateServiceWithDataExfiltration()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchCreateOrUpdateServiceWithDataExfiltration.json
            // this example is just showing the usage of "Services_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            SearchServiceData data = new SearchServiceData(new AzureLocation("westus"))
            {
                SearchSkuName = SearchServiceSkuName.Standard,
                ReplicaCount = 3,
                PartitionCount = 1,
                HostingMode = SearchServiceHostingMode.Default,
                ComputeType = SearchServiceComputeType.Default,
                DataExfiltrationProtections = { SearchDataExfiltrationProtection.BlockAll },
                Tags =
{
["app-name"] = "My e-commerce app"
},
            };
            ArmOperation<SearchServiceResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, searchServiceName, data);
            SearchServiceResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SearchServiceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_SearchCreateOrUpdateServiceWithIdentity()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchCreateOrUpdateServiceWithIdentity.json
            // this example is just showing the usage of "Services_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            SearchServiceData data = new SearchServiceData(new AzureLocation("westus"))
            {
                SearchSkuName = SearchServiceSkuName.Standard,
                Identity = new ManagedServiceIdentity("SystemAssigned, UserAssigned")
                {
                    UserAssignedIdentities =
{
[new ResourceIdentifier("/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/user-mi")] = new UserAssignedIdentity()
},
                },
                ReplicaCount = 3,
                PartitionCount = 1,
                HostingMode = SearchServiceHostingMode.Default,
                ComputeType = SearchServiceComputeType.Default,
                Tags =
{
["app-name"] = "My e-commerce app"
},
            };
            ArmOperation<SearchServiceResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, searchServiceName, data);
            SearchServiceResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SearchServiceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_SearchCreateOrUpdateWithSemanticSearch()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchCreateOrUpdateWithSemanticSearch.json
            // this example is just showing the usage of "Services_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            SearchServiceData data = new SearchServiceData(new AzureLocation("westus"))
            {
                SearchSkuName = SearchServiceSkuName.Standard,
                ReplicaCount = 3,
                PartitionCount = 1,
                HostingMode = SearchServiceHostingMode.Default,
                ComputeType = SearchServiceComputeType.Default,
                SemanticSearch = SearchSemanticSearch.Free,
                Tags =
{
["app-name"] = "My e-commerce app"
},
            };
            ArmOperation<SearchServiceResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, searchServiceName, data);
            SearchServiceResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SearchServiceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_SearchGetService()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchGetService.json
            // this example is just showing the usage of "Services_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            SearchServiceResource result = await collection.GetAsync(searchServiceName);

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SearchServiceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetAll_SearchListServicesByResourceGroup()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchListServicesByResourceGroup.json
            // this example is just showing the usage of "Services_ListByResourceGroup" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation and iterate over the result
            await foreach (SearchServiceResource item in collection.GetAllAsync())
            {
                // the variable item is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                SearchServiceData resourceData = item.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Exists_SearchGetService()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchGetService.json
            // this example is just showing the usage of "Services_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            bool result = await collection.ExistsAsync(searchServiceName);

            Console.WriteLine($"Succeeded: {result}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetIfExists_SearchGetService()
        {
            // Generated from example definition: specification/search/resource-manager/Microsoft.Search/stable/2025-05-01/examples/SearchGetService.json
            // this example is just showing the usage of "Services_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "subid";
            string resourceGroupName = "rg1";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this SearchServiceResource
            SearchServiceCollection collection = resourceGroupResource.GetSearchServices();

            // invoke the operation
            string searchServiceName = "mysearchservice";
            NullableResponse<SearchServiceResource> response = await collection.GetIfExistsAsync(searchServiceName);
            SearchServiceResource result = response.HasValue ? response.Value : null;

            if (result == null)
            {
                Console.WriteLine("Succeeded with null as result");
            }
            else
            {
                // the variable result is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                SearchServiceData resourceData = result.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }
        }
    }
}
