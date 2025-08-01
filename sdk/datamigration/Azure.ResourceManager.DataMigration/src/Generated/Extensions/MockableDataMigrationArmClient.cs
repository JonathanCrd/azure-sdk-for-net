// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using Azure.Core;

namespace Azure.ResourceManager.DataMigration.Mocking
{
    /// <summary> A class to add extension methods to ArmClient. </summary>
    public partial class MockableDataMigrationArmClient : ArmResource
    {
        /// <summary> Initializes a new instance of the <see cref="MockableDataMigrationArmClient"/> class for mocking. </summary>
        protected MockableDataMigrationArmClient()
        {
        }

        /// <summary> Initializes a new instance of the <see cref="MockableDataMigrationArmClient"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="id"> The identifier of the resource that is the target of operations. </param>
        internal MockableDataMigrationArmClient(ArmClient client, ResourceIdentifier id) : base(client, id)
        {
        }

        internal MockableDataMigrationArmClient(ArmClient client) : this(client, ResourceIdentifier.Root)
        {
        }

        private string GetApiVersionOrNull(ResourceType resourceType)
        {
            TryGetApiVersion(resourceType, out string apiVersion);
            return apiVersion;
        }

        /// <summary>
        /// Gets an object representing a <see cref="DatabaseMigrationSqlDBResource"/> along with the instance operations that can be performed on it but with no data.
        /// You can use <see cref="DatabaseMigrationSqlDBResource.CreateResourceIdentifier" /> to create a <see cref="DatabaseMigrationSqlDBResource"/> <see cref="ResourceIdentifier"/> from its components.
        /// </summary>
        /// <param name="id"> The resource ID of the resource to get. </param>
        /// <returns> Returns a <see cref="DatabaseMigrationSqlDBResource"/> object. </returns>
        public virtual DatabaseMigrationSqlDBResource GetDatabaseMigrationSqlDBResource(ResourceIdentifier id)
        {
            DatabaseMigrationSqlDBResource.ValidateResourceId(id);
            return new DatabaseMigrationSqlDBResource(Client, id);
        }

        /// <summary>
        /// Gets an object representing a <see cref="DatabaseMigrationSqlMIResource"/> along with the instance operations that can be performed on it but with no data.
        /// You can use <see cref="DatabaseMigrationSqlMIResource.CreateResourceIdentifier" /> to create a <see cref="DatabaseMigrationSqlMIResource"/> <see cref="ResourceIdentifier"/> from its components.
        /// </summary>
        /// <param name="id"> The resource ID of the resource to get. </param>
        /// <returns> Returns a <see cref="DatabaseMigrationSqlMIResource"/> object. </returns>
        public virtual DatabaseMigrationSqlMIResource GetDatabaseMigrationSqlMIResource(ResourceIdentifier id)
        {
            DatabaseMigrationSqlMIResource.ValidateResourceId(id);
            return new DatabaseMigrationSqlMIResource(Client, id);
        }

        /// <summary>
        /// Gets an object representing a <see cref="DatabaseMigrationSqlVmResource"/> along with the instance operations that can be performed on it but with no data.
        /// You can use <see cref="DatabaseMigrationSqlVmResource.CreateResourceIdentifier" /> to create a <see cref="DatabaseMigrationSqlVmResource"/> <see cref="ResourceIdentifier"/> from its components.
        /// </summary>
        /// <param name="id"> The resource ID of the resource to get. </param>
        /// <returns> Returns a <see cref="DatabaseMigrationSqlVmResource"/> object. </returns>
        public virtual DatabaseMigrationSqlVmResource GetDatabaseMigrationSqlVmResource(ResourceIdentifier id)
        {
            DatabaseMigrationSqlVmResource.ValidateResourceId(id);
            return new DatabaseMigrationSqlVmResource(Client, id);
        }

        /// <summary>
        /// Gets an object representing a <see cref="SqlMigrationServiceResource"/> along with the instance operations that can be performed on it but with no data.
        /// You can use <see cref="SqlMigrationServiceResource.CreateResourceIdentifier" /> to create a <see cref="SqlMigrationServiceResource"/> <see cref="ResourceIdentifier"/> from its components.
        /// </summary>
        /// <param name="id"> The resource ID of the resource to get. </param>
        /// <returns> Returns a <see cref="SqlMigrationServiceResource"/> object. </returns>
        public virtual SqlMigrationServiceResource GetSqlMigrationServiceResource(ResourceIdentifier id)
        {
            SqlMigrationServiceResource.ValidateResourceId(id);
            return new SqlMigrationServiceResource(Client, id);
        }

        /// <summary>
        /// Gets an object representing a <see cref="DataMigrationServiceResource"/> along with the instance operations that can be performed on it but with no data.
        /// You can use <see cref="DataMigrationServiceResource.CreateResourceIdentifier" /> to create a <see cref="DataMigrationServiceResource"/> <see cref="ResourceIdentifier"/> from its components.
        /// </summary>
        /// <param name="id"> The resource ID of the resource to get. </param>
        /// <returns> Returns a <see cref="DataMigrationServiceResource"/> object. </returns>
        public virtual DataMigrationServiceResource GetDataMigrationServiceResource(ResourceIdentifier id)
        {
            DataMigrationServiceResource.ValidateResourceId(id);
            return new DataMigrationServiceResource(Client, id);
        }

        /// <summary>
        /// Gets an object representing a <see cref="DataMigrationServiceTaskResource"/> along with the instance operations that can be performed on it but with no data.
        /// You can use <see cref="DataMigrationServiceTaskResource.CreateResourceIdentifier" /> to create a <see cref="DataMigrationServiceTaskResource"/> <see cref="ResourceIdentifier"/> from its components.
        /// </summary>
        /// <param name="id"> The resource ID of the resource to get. </param>
        /// <returns> Returns a <see cref="DataMigrationServiceTaskResource"/> object. </returns>
        public virtual DataMigrationServiceTaskResource GetDataMigrationServiceTaskResource(ResourceIdentifier id)
        {
            DataMigrationServiceTaskResource.ValidateResourceId(id);
            return new DataMigrationServiceTaskResource(Client, id);
        }

        /// <summary>
        /// Gets an object representing a <see cref="ServiceServiceTaskResource"/> along with the instance operations that can be performed on it but with no data.
        /// You can use <see cref="ServiceServiceTaskResource.CreateResourceIdentifier" /> to create a <see cref="ServiceServiceTaskResource"/> <see cref="ResourceIdentifier"/> from its components.
        /// </summary>
        /// <param name="id"> The resource ID of the resource to get. </param>
        /// <returns> Returns a <see cref="ServiceServiceTaskResource"/> object. </returns>
        public virtual ServiceServiceTaskResource GetServiceServiceTaskResource(ResourceIdentifier id)
        {
            ServiceServiceTaskResource.ValidateResourceId(id);
            return new ServiceServiceTaskResource(Client, id);
        }

        /// <summary>
        /// Gets an object representing a <see cref="DataMigrationProjectResource"/> along with the instance operations that can be performed on it but with no data.
        /// You can use <see cref="DataMigrationProjectResource.CreateResourceIdentifier" /> to create a <see cref="DataMigrationProjectResource"/> <see cref="ResourceIdentifier"/> from its components.
        /// </summary>
        /// <param name="id"> The resource ID of the resource to get. </param>
        /// <returns> Returns a <see cref="DataMigrationProjectResource"/> object. </returns>
        public virtual DataMigrationProjectResource GetDataMigrationProjectResource(ResourceIdentifier id)
        {
            DataMigrationProjectResource.ValidateResourceId(id);
            return new DataMigrationProjectResource(Client, id);
        }

        /// <summary>
        /// Gets an object representing a <see cref="DataMigrationProjectFileResource"/> along with the instance operations that can be performed on it but with no data.
        /// You can use <see cref="DataMigrationProjectFileResource.CreateResourceIdentifier" /> to create a <see cref="DataMigrationProjectFileResource"/> <see cref="ResourceIdentifier"/> from its components.
        /// </summary>
        /// <param name="id"> The resource ID of the resource to get. </param>
        /// <returns> Returns a <see cref="DataMigrationProjectFileResource"/> object. </returns>
        public virtual DataMigrationProjectFileResource GetDataMigrationProjectFileResource(ResourceIdentifier id)
        {
            DataMigrationProjectFileResource.ValidateResourceId(id);
            return new DataMigrationProjectFileResource(Client, id);
        }
    }
}
