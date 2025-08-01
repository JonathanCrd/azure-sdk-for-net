// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager.Sql.Models;
using NUnit.Framework;

namespace Azure.ResourceManager.Sql.Samples
{
    public partial class Sample_InstancePoolResource
    {
        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_GetAnInstancePool()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/GetInstancePool.json
            // this example is just showing the usage of "InstancePools_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this InstancePoolResource created on azure
            // for more information of creating InstancePoolResource, please refer to the document of InstancePoolResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "group1";
            string instancePoolName = "testIP";
            ResourceIdentifier instancePoolResourceId = InstancePoolResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, instancePoolName);
            InstancePoolResource instancePool = client.GetInstancePoolResource(instancePoolResourceId);

            // invoke the operation
            InstancePoolResource result = await instancePool.GetAsync();

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            InstancePoolData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Delete_DeleteAnInstancePool()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/DeleteInstancePool.json
            // this example is just showing the usage of "InstancePools_Delete" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this InstancePoolResource created on azure
            // for more information of creating InstancePoolResource, please refer to the document of InstancePoolResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "group1";
            string instancePoolName = "testIP";
            ResourceIdentifier instancePoolResourceId = InstancePoolResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, instancePoolName);
            InstancePoolResource instancePool = client.GetInstancePoolResource(instancePoolResourceId);

            // invoke the operation
            await instancePool.DeleteAsync(WaitUntil.Completed);

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Update_PatchAnInstancePool()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/PatchInstancePool.json
            // this example is just showing the usage of "InstancePools_Update" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this InstancePoolResource created on azure
            // for more information of creating InstancePoolResource, please refer to the document of InstancePoolResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "group1";
            string instancePoolName = "testIP";
            ResourceIdentifier instancePoolResourceId = InstancePoolResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, instancePoolName);
            InstancePoolResource instancePool = client.GetInstancePoolResource(instancePoolResourceId);

            // invoke the operation
            InstancePoolPatch patch = new InstancePoolPatch
            {
                Tags =
{
["x"] = "y"
},
            };
            ArmOperation<InstancePoolResource> lro = await instancePool.UpdateAsync(WaitUntil.Completed, patch);
            InstancePoolResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            InstancePoolData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetManagedInstances_ListManagedInstancesByInstancePool()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ManagedInstanceListByInstancePool.json
            // this example is just showing the usage of "ManagedInstances_ListByInstancePool" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this InstancePoolResource created on azure
            // for more information of creating InstancePoolResource, please refer to the document of InstancePoolResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "Test1";
            string instancePoolName = "pool1";
            ResourceIdentifier instancePoolResourceId = InstancePoolResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, instancePoolName);
            InstancePoolResource instancePool = client.GetInstancePoolResource(instancePoolResourceId);

            // invoke the operation and iterate over the result
            await foreach (ManagedInstanceResource item in instancePool.GetManagedInstancesAsync())
            {
                // the variable item is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                ManagedInstanceData resourceData = item.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetManagedInstances_ListManagedInstancesByInstancePoolWithExpandAdministratorsActivedirectory()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ManagedInstanceListByInstancePoolWithExpandEqualsAdministrators.json
            // this example is just showing the usage of "ManagedInstances_ListByInstancePool" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this InstancePoolResource created on azure
            // for more information of creating InstancePoolResource, please refer to the document of InstancePoolResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "Test1";
            string instancePoolName = "pool1";
            ResourceIdentifier instancePoolResourceId = InstancePoolResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, instancePoolName);
            InstancePoolResource instancePool = client.GetInstancePoolResource(instancePoolResourceId);

            // invoke the operation and iterate over the result
            await foreach (ManagedInstanceResource item in instancePool.GetManagedInstancesAsync())
            {
                // the variable item is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                ManagedInstanceData resourceData = item.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetUsages_ListInstancePoolUsagesExpandedWithChildren()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ListInstancePoolUsageExpanded.json
            // this example is just showing the usage of "Usages_ListByInstancePool" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this InstancePoolResource created on azure
            // for more information of creating InstancePoolResource, please refer to the document of InstancePoolResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "group1";
            string instancePoolName = "testIP";
            ResourceIdentifier instancePoolResourceId = InstancePoolResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, instancePoolName);
            InstancePoolResource instancePool = client.GetInstancePoolResource(instancePoolResourceId);

            // invoke the operation and iterate over the result
            bool? expandChildren = true;
            await foreach (InstancePoolUsage item in instancePool.GetUsagesAsync(expandChildren: expandChildren))
            {
                Console.WriteLine($"Succeeded: {item}");
            }

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetUsages_ListInstancePoolUsages()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ListInstancePoolUsage.json
            // this example is just showing the usage of "Usages_ListByInstancePool" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this InstancePoolResource created on azure
            // for more information of creating InstancePoolResource, please refer to the document of InstancePoolResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "group1";
            string instancePoolName = "testIP";
            ResourceIdentifier instancePoolResourceId = InstancePoolResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, instancePoolName);
            InstancePoolResource instancePool = client.GetInstancePoolResource(instancePoolResourceId);

            // invoke the operation and iterate over the result
            await foreach (InstancePoolUsage item in instancePool.GetUsagesAsync())
            {
                Console.WriteLine($"Succeeded: {item}");
            }

            Console.WriteLine("Succeeded");
        }
    }
}
