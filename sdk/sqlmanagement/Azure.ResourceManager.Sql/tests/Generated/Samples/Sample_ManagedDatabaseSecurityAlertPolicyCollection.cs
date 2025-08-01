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
    public partial class Sample_ManagedDatabaseSecurityAlertPolicyCollection
    {
        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_UpdateADatabaseSThreatDetectionPolicyWithAllParameters()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ManagedDatabaseSecurityAlertCreateMax.json
            // this example is just showing the usage of "ManagedDatabaseSecurityAlertPolicies_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ManagedDatabaseResource created on azure
            // for more information of creating ManagedDatabaseResource, please refer to the document of ManagedDatabaseResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "securityalert-4799";
            string managedInstanceName = "securityalert-6440";
            string databaseName = "testdb";
            ResourceIdentifier managedDatabaseResourceId = ManagedDatabaseResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, managedInstanceName, databaseName);
            ManagedDatabaseResource managedDatabase = client.GetManagedDatabaseResource(managedDatabaseResourceId);

            // get the collection of this ManagedDatabaseSecurityAlertPolicyResource
            ManagedDatabaseSecurityAlertPolicyCollection collection = managedDatabase.GetManagedDatabaseSecurityAlertPolicies();

            // invoke the operation
            SqlSecurityAlertPolicyName securityAlertPolicyName = new SqlSecurityAlertPolicyName("default");
            ManagedDatabaseSecurityAlertPolicyData data = new ManagedDatabaseSecurityAlertPolicyData
            {
                State = SecurityAlertPolicyState.Enabled,
                DisabledAlerts = { "Sql_Injection", "Usage_Anomaly" },
                EmailAddresses = { "test@contoso.com", "user@contoso.com" },
                SendToEmailAccountAdmins = true,
                StorageEndpoint = "https://mystorage.blob.core.windows.net",
                StorageAccountAccessKey = "sdlfkjabc+sdlfkjsdlkfsjdfLDKFTERLKFDFKLjsdfksjdflsdkfD2342309432849328476458/3RSD==",
                RetentionDays = 6,
            };
            ArmOperation<ManagedDatabaseSecurityAlertPolicyResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, securityAlertPolicyName, data);
            ManagedDatabaseSecurityAlertPolicyResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            ManagedDatabaseSecurityAlertPolicyData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_UpdateADatabaseSThreatDetectionPolicyWithMinimalParameters()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ManagedDatabaseSecurityAlertCreateMin.json
            // this example is just showing the usage of "ManagedDatabaseSecurityAlertPolicies_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ManagedDatabaseResource created on azure
            // for more information of creating ManagedDatabaseResource, please refer to the document of ManagedDatabaseResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "securityalert-4799";
            string managedInstanceName = "securityalert-6440";
            string databaseName = "testdb";
            ResourceIdentifier managedDatabaseResourceId = ManagedDatabaseResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, managedInstanceName, databaseName);
            ManagedDatabaseResource managedDatabase = client.GetManagedDatabaseResource(managedDatabaseResourceId);

            // get the collection of this ManagedDatabaseSecurityAlertPolicyResource
            ManagedDatabaseSecurityAlertPolicyCollection collection = managedDatabase.GetManagedDatabaseSecurityAlertPolicies();

            // invoke the operation
            SqlSecurityAlertPolicyName securityAlertPolicyName = new SqlSecurityAlertPolicyName("default");
            ManagedDatabaseSecurityAlertPolicyData data = new ManagedDatabaseSecurityAlertPolicyData
            {
                State = SecurityAlertPolicyState.Enabled,
            };
            ArmOperation<ManagedDatabaseSecurityAlertPolicyResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, securityAlertPolicyName, data);
            ManagedDatabaseSecurityAlertPolicyResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            ManagedDatabaseSecurityAlertPolicyData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_GetADatabaseSThreatDetectionPolicy()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ManagedDatabaseSecurityAlertGet.json
            // this example is just showing the usage of "ManagedDatabaseSecurityAlertPolicies_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ManagedDatabaseResource created on azure
            // for more information of creating ManagedDatabaseResource, please refer to the document of ManagedDatabaseResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "securityalert-6852";
            string managedInstanceName = "securityalert-2080";
            string databaseName = "testdb";
            ResourceIdentifier managedDatabaseResourceId = ManagedDatabaseResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, managedInstanceName, databaseName);
            ManagedDatabaseResource managedDatabase = client.GetManagedDatabaseResource(managedDatabaseResourceId);

            // get the collection of this ManagedDatabaseSecurityAlertPolicyResource
            ManagedDatabaseSecurityAlertPolicyCollection collection = managedDatabase.GetManagedDatabaseSecurityAlertPolicies();

            // invoke the operation
            SqlSecurityAlertPolicyName securityAlertPolicyName = new SqlSecurityAlertPolicyName("default");
            ManagedDatabaseSecurityAlertPolicyResource result = await collection.GetAsync(securityAlertPolicyName);

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            ManagedDatabaseSecurityAlertPolicyData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetAll_GetAListOfTheDatabaseSThreatDetectionPolicies()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ManagedDatabaseSecurityAlertListByDatabase.json
            // this example is just showing the usage of "ManagedDatabaseSecurityAlertPolicies_ListByDatabase" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ManagedDatabaseResource created on azure
            // for more information of creating ManagedDatabaseResource, please refer to the document of ManagedDatabaseResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "securityalert-6852";
            string managedInstanceName = "securityalert-2080";
            string databaseName = "testdb";
            ResourceIdentifier managedDatabaseResourceId = ManagedDatabaseResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, managedInstanceName, databaseName);
            ManagedDatabaseResource managedDatabase = client.GetManagedDatabaseResource(managedDatabaseResourceId);

            // get the collection of this ManagedDatabaseSecurityAlertPolicyResource
            ManagedDatabaseSecurityAlertPolicyCollection collection = managedDatabase.GetManagedDatabaseSecurityAlertPolicies();

            // invoke the operation and iterate over the result
            await foreach (ManagedDatabaseSecurityAlertPolicyResource item in collection.GetAllAsync())
            {
                // the variable item is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                ManagedDatabaseSecurityAlertPolicyData resourceData = item.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Exists_GetADatabaseSThreatDetectionPolicy()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ManagedDatabaseSecurityAlertGet.json
            // this example is just showing the usage of "ManagedDatabaseSecurityAlertPolicies_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ManagedDatabaseResource created on azure
            // for more information of creating ManagedDatabaseResource, please refer to the document of ManagedDatabaseResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "securityalert-6852";
            string managedInstanceName = "securityalert-2080";
            string databaseName = "testdb";
            ResourceIdentifier managedDatabaseResourceId = ManagedDatabaseResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, managedInstanceName, databaseName);
            ManagedDatabaseResource managedDatabase = client.GetManagedDatabaseResource(managedDatabaseResourceId);

            // get the collection of this ManagedDatabaseSecurityAlertPolicyResource
            ManagedDatabaseSecurityAlertPolicyCollection collection = managedDatabase.GetManagedDatabaseSecurityAlertPolicies();

            // invoke the operation
            SqlSecurityAlertPolicyName securityAlertPolicyName = new SqlSecurityAlertPolicyName("default");
            bool result = await collection.ExistsAsync(securityAlertPolicyName);

            Console.WriteLine($"Succeeded: {result}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetIfExists_GetADatabaseSThreatDetectionPolicy()
        {
            // Generated from example definition: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ManagedDatabaseSecurityAlertGet.json
            // this example is just showing the usage of "ManagedDatabaseSecurityAlertPolicies_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ManagedDatabaseResource created on azure
            // for more information of creating ManagedDatabaseResource, please refer to the document of ManagedDatabaseResource
            string subscriptionId = "00000000-1111-2222-3333-444444444444";
            string resourceGroupName = "securityalert-6852";
            string managedInstanceName = "securityalert-2080";
            string databaseName = "testdb";
            ResourceIdentifier managedDatabaseResourceId = ManagedDatabaseResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, managedInstanceName, databaseName);
            ManagedDatabaseResource managedDatabase = client.GetManagedDatabaseResource(managedDatabaseResourceId);

            // get the collection of this ManagedDatabaseSecurityAlertPolicyResource
            ManagedDatabaseSecurityAlertPolicyCollection collection = managedDatabase.GetManagedDatabaseSecurityAlertPolicies();

            // invoke the operation
            SqlSecurityAlertPolicyName securityAlertPolicyName = new SqlSecurityAlertPolicyName("default");
            NullableResponse<ManagedDatabaseSecurityAlertPolicyResource> response = await collection.GetIfExistsAsync(securityAlertPolicyName);
            ManagedDatabaseSecurityAlertPolicyResource result = response.HasValue ? response.Value : null;

            if (result == null)
            {
                Console.WriteLine("Succeeded with null as result");
            }
            else
            {
                // the variable result is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                ManagedDatabaseSecurityAlertPolicyData resourceData = result.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }
        }
    }
}
