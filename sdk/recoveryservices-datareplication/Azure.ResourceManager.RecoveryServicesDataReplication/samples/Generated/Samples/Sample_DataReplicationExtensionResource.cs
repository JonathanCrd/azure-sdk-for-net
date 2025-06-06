// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager.RecoveryServicesDataReplication.Models;
using NUnit.Framework;

namespace Azure.ResourceManager.RecoveryServicesDataReplication.Samples
{
    public partial class Sample_DataReplicationExtensionResource
    {
        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_GetsTheReplicationExtension()
        {
            // Generated from example definition: 2024-09-01/ReplicationExtension_Get.json
            // this example is just showing the usage of "ReplicationExtensionModel_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this DataReplicationExtensionResource created on azure
            // for more information of creating DataReplicationExtensionResource, please refer to the document of DataReplicationExtensionResource
            string subscriptionId = "930CEC23-4430-4513-B855-DBA237E2F3BF";
            string resourceGroupName = "rgrecoveryservicesdatareplication";
            string vaultName = "4";
            string replicationExtensionName = "g16yjJ";
            ResourceIdentifier dataReplicationExtensionResourceId = DataReplicationExtensionResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, vaultName, replicationExtensionName);
            DataReplicationExtensionResource dataReplicationExtension = client.GetDataReplicationExtensionResource(dataReplicationExtensionResourceId);

            // invoke the operation
            DataReplicationExtensionResource result = await dataReplicationExtension.GetAsync();

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            DataReplicationExtensionData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Delete_DeletesTheReplicationExtension()
        {
            // Generated from example definition: 2024-09-01/ReplicationExtension_Delete.json
            // this example is just showing the usage of "ReplicationExtensionModel_Delete" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this DataReplicationExtensionResource created on azure
            // for more information of creating DataReplicationExtensionResource, please refer to the document of DataReplicationExtensionResource
            string subscriptionId = "930CEC23-4430-4513-B855-DBA237E2F3BF";
            string resourceGroupName = "rgrecoveryservicesdatareplication";
            string vaultName = "4";
            string replicationExtensionName = "g16yjJ";
            ResourceIdentifier dataReplicationExtensionResourceId = DataReplicationExtensionResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, vaultName, replicationExtensionName);
            DataReplicationExtensionResource dataReplicationExtension = client.GetDataReplicationExtensionResource(dataReplicationExtensionResourceId);

            // invoke the operation
            await dataReplicationExtension.DeleteAsync(WaitUntil.Completed);

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Update_PutsTheReplicationExtension()
        {
            // Generated from example definition: 2024-09-01/ReplicationExtension_Create.json
            // this example is just showing the usage of "ReplicationExtensionModel_Create" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this DataReplicationExtensionResource created on azure
            // for more information of creating DataReplicationExtensionResource, please refer to the document of DataReplicationExtensionResource
            string subscriptionId = "930CEC23-4430-4513-B855-DBA237E2F3BF";
            string resourceGroupName = "rgrecoveryservicesdatareplication";
            string vaultName = "4";
            string replicationExtensionName = "g16yjJ";
            ResourceIdentifier dataReplicationExtensionResourceId = DataReplicationExtensionResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, vaultName, replicationExtensionName);
            DataReplicationExtensionResource dataReplicationExtension = client.GetDataReplicationExtensionResource(dataReplicationExtensionResourceId);

            // invoke the operation
            DataReplicationExtensionData data = new DataReplicationExtensionData
            {
                Properties = new DataReplicationExtensionProperties(default),
            };
            ArmOperation<DataReplicationExtensionResource> lro = await dataReplicationExtension.UpdateAsync(WaitUntil.Completed, data);
            DataReplicationExtensionResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            DataReplicationExtensionData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }
    }
}
