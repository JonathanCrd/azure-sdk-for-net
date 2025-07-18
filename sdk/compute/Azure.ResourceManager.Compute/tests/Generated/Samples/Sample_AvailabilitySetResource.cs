// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager.Compute.Models;
using Azure.ResourceManager.Resources.Models;
using NUnit.Framework;

namespace Azure.ResourceManager.Compute.Samples
{
    public partial class Sample_AvailabilitySetResource
    {
        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_AvailabilitySetGetMaximumSetGen()
        {
            // Generated from example definition: specification/compute/resource-manager/Microsoft.Compute/ComputeRP/stable/2024-11-01/examples/availabilitySetExamples/AvailabilitySet_Get_MaximumSet_Gen.json
            // this example is just showing the usage of "AvailabilitySets_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this AvailabilitySetResource created on azure
            // for more information of creating AvailabilitySetResource, please refer to the document of AvailabilitySetResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "rgcompute";
            string availabilitySetName = "aaaaaaaaaaaa";
            ResourceIdentifier availabilitySetResourceId = AvailabilitySetResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, availabilitySetName);
            AvailabilitySetResource availabilitySet = client.GetAvailabilitySetResource(availabilitySetResourceId);

            // invoke the operation
            AvailabilitySetResource result = await availabilitySet.GetAsync();

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            AvailabilitySetData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_AvailabilitySetGetMinimumSetGen()
        {
            // Generated from example definition: specification/compute/resource-manager/Microsoft.Compute/ComputeRP/stable/2024-11-01/examples/availabilitySetExamples/AvailabilitySet_Get_MinimumSet_Gen.json
            // this example is just showing the usage of "AvailabilitySets_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this AvailabilitySetResource created on azure
            // for more information of creating AvailabilitySetResource, please refer to the document of AvailabilitySetResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "rgcompute";
            string availabilitySetName = "aaaaaaaaaaaaaaaaaaaa";
            ResourceIdentifier availabilitySetResourceId = AvailabilitySetResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, availabilitySetName);
            AvailabilitySetResource availabilitySet = client.GetAvailabilitySetResource(availabilitySetResourceId);

            // invoke the operation
            AvailabilitySetResource result = await availabilitySet.GetAsync();

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            AvailabilitySetData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Delete_AvailabilitySetDeleteMaximumSetGen()
        {
            // Generated from example definition: specification/compute/resource-manager/Microsoft.Compute/ComputeRP/stable/2024-11-01/examples/availabilitySetExamples/AvailabilitySet_Delete_MaximumSet_Gen.json
            // this example is just showing the usage of "AvailabilitySets_Delete" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this AvailabilitySetResource created on azure
            // for more information of creating AvailabilitySetResource, please refer to the document of AvailabilitySetResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "rgcompute";
            string availabilitySetName = "aaaaaaaaaaaaaaaaaaaa";
            ResourceIdentifier availabilitySetResourceId = AvailabilitySetResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, availabilitySetName);
            AvailabilitySetResource availabilitySet = client.GetAvailabilitySetResource(availabilitySetResourceId);

            // invoke the operation
            await availabilitySet.DeleteAsync(WaitUntil.Completed);

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Delete_AvailabilitySetDeleteMinimumSetGen()
        {
            // Generated from example definition: specification/compute/resource-manager/Microsoft.Compute/ComputeRP/stable/2024-11-01/examples/availabilitySetExamples/AvailabilitySet_Delete_MinimumSet_Gen.json
            // this example is just showing the usage of "AvailabilitySets_Delete" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this AvailabilitySetResource created on azure
            // for more information of creating AvailabilitySetResource, please refer to the document of AvailabilitySetResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "rgcompute";
            string availabilitySetName = "aaaaaaaaaaa";
            ResourceIdentifier availabilitySetResourceId = AvailabilitySetResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, availabilitySetName);
            AvailabilitySetResource availabilitySet = client.GetAvailabilitySetResource(availabilitySetResourceId);

            // invoke the operation
            await availabilitySet.DeleteAsync(WaitUntil.Completed);

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Update_AvailabilitySetUpdateMaximumSetGen()
        {
            // Generated from example definition: specification/compute/resource-manager/Microsoft.Compute/ComputeRP/stable/2024-11-01/examples/availabilitySetExamples/AvailabilitySet_Update_MaximumSet_Gen.json
            // this example is just showing the usage of "AvailabilitySets_Update" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this AvailabilitySetResource created on azure
            // for more information of creating AvailabilitySetResource, please refer to the document of AvailabilitySetResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "rgcompute";
            string availabilitySetName = "aaaaaaaaaaaaaaaaaaa";
            ResourceIdentifier availabilitySetResourceId = AvailabilitySetResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, availabilitySetName);
            AvailabilitySetResource availabilitySet = client.GetAvailabilitySetResource(availabilitySetResourceId);

            // invoke the operation
            AvailabilitySetPatch patch = new AvailabilitySetPatch
            {
                Sku = new ComputeSku
                {
                    Name = "DSv3-Type1",
                    Tier = "aaa",
                    Capacity = 7L,
                },
                PlatformUpdateDomainCount = 20,
                PlatformFaultDomainCount = 2,
                VirtualMachines = {new WritableSubResource
{
Id = new ResourceIdentifier("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/availabilitySets/{availabilitySetName}"),
}},
                ProximityPlacementGroupId = new ResourceIdentifier("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/availabilitySets/{availabilitySetName}"),
                Tags =
{
["key2574"] = "aaaaaaaa"
},
            };
            AvailabilitySetResource result = await availabilitySet.UpdateAsync(patch);

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            AvailabilitySetData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Update_AvailabilitySetUpdateMinimumSetGen()
        {
            // Generated from example definition: specification/compute/resource-manager/Microsoft.Compute/ComputeRP/stable/2024-11-01/examples/availabilitySetExamples/AvailabilitySet_Update_MinimumSet_Gen.json
            // this example is just showing the usage of "AvailabilitySets_Update" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this AvailabilitySetResource created on azure
            // for more information of creating AvailabilitySetResource, please refer to the document of AvailabilitySetResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "rgcompute";
            string availabilitySetName = "aaaaaaaaaaaaaaaaaaaa";
            ResourceIdentifier availabilitySetResourceId = AvailabilitySetResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, availabilitySetName);
            AvailabilitySetResource availabilitySet = client.GetAvailabilitySetResource(availabilitySetResourceId);

            // invoke the operation
            AvailabilitySetPatch patch = new AvailabilitySetPatch();
            AvailabilitySetResource result = await availabilitySet.UpdateAsync(patch);

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            AvailabilitySetData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CancelMigrationToVirtualMachineScaleSet_AvailabilitySetCancelMigrationToVirtualMachineScaleSet()
        {
            // Generated from example definition: specification/compute/resource-manager/Microsoft.Compute/ComputeRP/stable/2024-11-01/examples/availabilitySetExamples/AvailabilitySet_CancelMigrationToVirtualMachineScaleSet.json
            // this example is just showing the usage of "AvailabilitySets_CancelMigrationToVirtualMachineScaleSet" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this AvailabilitySetResource created on azure
            // for more information of creating AvailabilitySetResource, please refer to the document of AvailabilitySetResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "rgcompute";
            string availabilitySetName = "myAvailabilitySet";
            ResourceIdentifier availabilitySetResourceId = AvailabilitySetResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, availabilitySetName);
            AvailabilitySetResource availabilitySet = client.GetAvailabilitySetResource(availabilitySetResourceId);

            // invoke the operation
            await availabilitySet.CancelMigrationToVirtualMachineScaleSetAsync();

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task ConvertToVirtualMachineScaleSet_AvailabilitySetConvertToVirtualMachineScaleSetGen()
        {
            // Generated from example definition: specification/compute/resource-manager/Microsoft.Compute/ComputeRP/stable/2024-11-01/examples/availabilitySetExamples/AvailabilitySet_ConvertToVirtualMachineScaleSet.json
            // this example is just showing the usage of "AvailabilitySets_ConvertToVirtualMachineScaleSet" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this AvailabilitySetResource created on azure
            // for more information of creating AvailabilitySetResource, please refer to the document of AvailabilitySetResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "rgcompute";
            string availabilitySetName = "myAvailabilitySet";
            ResourceIdentifier availabilitySetResourceId = AvailabilitySetResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, availabilitySetName);
            AvailabilitySetResource availabilitySet = client.GetAvailabilitySetResource(availabilitySetResourceId);

            // invoke the operation
            ConvertToVirtualMachineScaleSetContent content = new ConvertToVirtualMachineScaleSetContent
            {
                VirtualMachineScaleSetName = "{vmss-name}",
            };
            await availabilitySet.ConvertToVirtualMachineScaleSetAsync(WaitUntil.Completed, content: content);

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task StartMigrationToVirtualMachineScaleSet_AvailabilitySetStartMigrationToVirtualMachineScaleSetGen()
        {
            // Generated from example definition: specification/compute/resource-manager/Microsoft.Compute/ComputeRP/stable/2024-11-01/examples/availabilitySetExamples/AvailabilitySet_StartMigrationToVirtualMachineScaleSet.json
            // this example is just showing the usage of "AvailabilitySets_StartMigrationToVirtualMachineScaleSet" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this AvailabilitySetResource created on azure
            // for more information of creating AvailabilitySetResource, please refer to the document of AvailabilitySetResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "rgcompute";
            string availabilitySetName = "myAvailabilitySet";
            ResourceIdentifier availabilitySetResourceId = AvailabilitySetResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, availabilitySetName);
            AvailabilitySetResource availabilitySet = client.GetAvailabilitySetResource(availabilitySetResourceId);

            // invoke the operation
            MigrateToVirtualMachineScaleSetInput input = new MigrateToVirtualMachineScaleSetInput(new WritableSubResource
            {
                Id = new ResourceIdentifier("/subscriptions/{subscription-id}/resourceGroups/rgcompute/providers/Microsoft.Compute/virtualMachineScaleSets/{vmss-name}"),
            });
            await availabilitySet.StartMigrationToVirtualMachineScaleSetAsync(input);

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task ValidateMigrationToVirtualMachineScaleSet_AvailabilitySetValidateMigrationToVirtualMachineScaleSet()
        {
            // Generated from example definition: specification/compute/resource-manager/Microsoft.Compute/ComputeRP/stable/2024-11-01/examples/availabilitySetExamples/AvailabilitySet_ValidateMigrationToVirtualMachineScaleSet.json
            // this example is just showing the usage of "AvailabilitySets_ValidateMigrationToVirtualMachineScaleSet" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this AvailabilitySetResource created on azure
            // for more information of creating AvailabilitySetResource, please refer to the document of AvailabilitySetResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "rgcompute";
            string availabilitySetName = "myAvailabilitySet";
            ResourceIdentifier availabilitySetResourceId = AvailabilitySetResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, availabilitySetName);
            AvailabilitySetResource availabilitySet = client.GetAvailabilitySetResource(availabilitySetResourceId);

            // invoke the operation
            MigrateToVirtualMachineScaleSetInput input = new MigrateToVirtualMachineScaleSetInput(new WritableSubResource
            {
                Id = new ResourceIdentifier("/subscriptions/{subscription-id}/resourceGroups/rgcompute/providers/Microsoft.Compute/virtualMachineScaleSets/{vmss-name}"),
            });
            await availabilitySet.ValidateMigrationToVirtualMachineScaleSetAsync(input);

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetAvailableSizes_AvailabilitySetListAvailableSizesMaximumSetGen()
        {
            // Generated from example definition: specification/compute/resource-manager/Microsoft.Compute/ComputeRP/stable/2024-11-01/examples/availabilitySetExamples/AvailabilitySet_ListAvailableSizes_MaximumSet_Gen.json
            // this example is just showing the usage of "AvailabilitySets_ListAvailableSizes" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this AvailabilitySetResource created on azure
            // for more information of creating AvailabilitySetResource, please refer to the document of AvailabilitySetResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "rgcompute";
            string availabilitySetName = "aaaaaaaaaaaaaaaaaaaa";
            ResourceIdentifier availabilitySetResourceId = AvailabilitySetResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, availabilitySetName);
            AvailabilitySetResource availabilitySet = client.GetAvailabilitySetResource(availabilitySetResourceId);

            // invoke the operation and iterate over the result
            await foreach (VirtualMachineSize item in availabilitySet.GetAvailableSizesAsync())
            {
                Console.WriteLine($"Succeeded: {item}");
            }

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetAvailableSizes_AvailabilitySetListAvailableSizesMinimumSetGen()
        {
            // Generated from example definition: specification/compute/resource-manager/Microsoft.Compute/ComputeRP/stable/2024-11-01/examples/availabilitySetExamples/AvailabilitySet_ListAvailableSizes_MinimumSet_Gen.json
            // this example is just showing the usage of "AvailabilitySets_ListAvailableSizes" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this AvailabilitySetResource created on azure
            // for more information of creating AvailabilitySetResource, please refer to the document of AvailabilitySetResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "rgcompute";
            string availabilitySetName = "aa";
            ResourceIdentifier availabilitySetResourceId = AvailabilitySetResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, availabilitySetName);
            AvailabilitySetResource availabilitySet = client.GetAvailabilitySetResource(availabilitySetResourceId);

            // invoke the operation and iterate over the result
            await foreach (VirtualMachineSize item in availabilitySet.GetAvailableSizesAsync())
            {
                Console.WriteLine($"Succeeded: {item}");
            }

            Console.WriteLine("Succeeded");
        }
    }
}
