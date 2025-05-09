// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using NUnit.Framework;

namespace Azure.ResourceManager.MigrationDiscoverySap.Samples
{
    public partial class Sample_SapInstanceCollection
    {
        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_CreatesTheSAPInstanceResource()
        {
            // Generated from example definition: specification/workloads/resource-manager/Microsoft.Workloads/SAPDiscoverySites/preview/2023-10-01-preview/examples/SAPInstances_Create.json
            // this example is just showing the usage of "SapInstances_Create" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SapDiscoverySiteResource created on azure
            // for more information of creating SapDiscoverySiteResource, please refer to the document of SapDiscoverySiteResource
            string subscriptionId = "6d875e77-e412-4d7d-9af4-8895278b4443";
            string resourceGroupName = "test-rg";
            string sapDiscoverySiteName = "SampleSite";
            ResourceIdentifier sapDiscoverySiteResourceId = SapDiscoverySiteResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, sapDiscoverySiteName);
            SapDiscoverySiteResource sapDiscoverySite = client.GetSapDiscoverySiteResource(sapDiscoverySiteResourceId);

            // get the collection of this SapInstanceResource
            SapInstanceCollection collection = sapDiscoverySite.GetSapInstances();

            // invoke the operation
            string sapInstanceName = "MPP_MPP";
            SapInstanceData data = new SapInstanceData(new AzureLocation("eastus"))
            {
                Tags =
{
["property1"] = "value1",
["property2"] = "value2"
},
            };
            ArmOperation<SapInstanceResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, sapInstanceName, data);
            SapInstanceResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SapInstanceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_GETASAPInstanceResource()
        {
            // Generated from example definition: specification/workloads/resource-manager/Microsoft.Workloads/SAPDiscoverySites/preview/2023-10-01-preview/examples/SAPInstances_Get.json
            // this example is just showing the usage of "SapInstances_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SapDiscoverySiteResource created on azure
            // for more information of creating SapDiscoverySiteResource, please refer to the document of SapDiscoverySiteResource
            string subscriptionId = "6d875e77-e412-4d7d-9af4-8895278b4443";
            string resourceGroupName = "test-rg";
            string sapDiscoverySiteName = "SampleSite";
            ResourceIdentifier sapDiscoverySiteResourceId = SapDiscoverySiteResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, sapDiscoverySiteName);
            SapDiscoverySiteResource sapDiscoverySite = client.GetSapDiscoverySiteResource(sapDiscoverySiteResourceId);

            // get the collection of this SapInstanceResource
            SapInstanceCollection collection = sapDiscoverySite.GetSapInstances();

            // invoke the operation
            string sapInstanceName = "MPP_MPP";
            SapInstanceResource result = await collection.GetAsync(sapInstanceName);

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            SapInstanceData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetAll_ListsTheSAPInstanceResourcesForTheGivenSAPMigrationDiscoverySiteResource()
        {
            // Generated from example definition: specification/workloads/resource-manager/Microsoft.Workloads/SAPDiscoverySites/preview/2023-10-01-preview/examples/SAPInstances_List.json
            // this example is just showing the usage of "SapInstances_ListBySapDiscoverySite" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SapDiscoverySiteResource created on azure
            // for more information of creating SapDiscoverySiteResource, please refer to the document of SapDiscoverySiteResource
            string subscriptionId = "6d875e77-e412-4d7d-9af4-8895278b4443";
            string resourceGroupName = "test-rg";
            string sapDiscoverySiteName = "SampleSite";
            ResourceIdentifier sapDiscoverySiteResourceId = SapDiscoverySiteResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, sapDiscoverySiteName);
            SapDiscoverySiteResource sapDiscoverySite = client.GetSapDiscoverySiteResource(sapDiscoverySiteResourceId);

            // get the collection of this SapInstanceResource
            SapInstanceCollection collection = sapDiscoverySite.GetSapInstances();

            // invoke the operation and iterate over the result
            await foreach (SapInstanceResource item in collection.GetAllAsync())
            {
                // the variable item is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                SapInstanceData resourceData = item.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Exists_GETASAPInstanceResource()
        {
            // Generated from example definition: specification/workloads/resource-manager/Microsoft.Workloads/SAPDiscoverySites/preview/2023-10-01-preview/examples/SAPInstances_Get.json
            // this example is just showing the usage of "SapInstances_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SapDiscoverySiteResource created on azure
            // for more information of creating SapDiscoverySiteResource, please refer to the document of SapDiscoverySiteResource
            string subscriptionId = "6d875e77-e412-4d7d-9af4-8895278b4443";
            string resourceGroupName = "test-rg";
            string sapDiscoverySiteName = "SampleSite";
            ResourceIdentifier sapDiscoverySiteResourceId = SapDiscoverySiteResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, sapDiscoverySiteName);
            SapDiscoverySiteResource sapDiscoverySite = client.GetSapDiscoverySiteResource(sapDiscoverySiteResourceId);

            // get the collection of this SapInstanceResource
            SapInstanceCollection collection = sapDiscoverySite.GetSapInstances();

            // invoke the operation
            string sapInstanceName = "MPP_MPP";
            bool result = await collection.ExistsAsync(sapInstanceName);

            Console.WriteLine($"Succeeded: {result}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetIfExists_GETASAPInstanceResource()
        {
            // Generated from example definition: specification/workloads/resource-manager/Microsoft.Workloads/SAPDiscoverySites/preview/2023-10-01-preview/examples/SAPInstances_Get.json
            // this example is just showing the usage of "SapInstances_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this SapDiscoverySiteResource created on azure
            // for more information of creating SapDiscoverySiteResource, please refer to the document of SapDiscoverySiteResource
            string subscriptionId = "6d875e77-e412-4d7d-9af4-8895278b4443";
            string resourceGroupName = "test-rg";
            string sapDiscoverySiteName = "SampleSite";
            ResourceIdentifier sapDiscoverySiteResourceId = SapDiscoverySiteResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, sapDiscoverySiteName);
            SapDiscoverySiteResource sapDiscoverySite = client.GetSapDiscoverySiteResource(sapDiscoverySiteResourceId);

            // get the collection of this SapInstanceResource
            SapInstanceCollection collection = sapDiscoverySite.GetSapInstances();

            // invoke the operation
            string sapInstanceName = "MPP_MPP";
            NullableResponse<SapInstanceResource> response = await collection.GetIfExistsAsync(sapInstanceName);
            SapInstanceResource result = response.HasValue ? response.Value : null;

            if (result == null)
            {
                Console.WriteLine("Succeeded with null as result");
            }
            else
            {
                // the variable result is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                SapInstanceData resourceData = result.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }
        }
    }
}
