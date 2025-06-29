// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Autorest.CSharp.Core;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager.Resources;

namespace Azure.ResourceManager.OracleDatabase
{
    /// <summary>
    /// A class representing a collection of <see cref="AutonomousDBVersionResource"/> and their operations.
    /// Each <see cref="AutonomousDBVersionResource"/> in the collection will belong to the same instance of <see cref="SubscriptionResource"/>.
    /// To get an <see cref="AutonomousDBVersionCollection"/> instance call the GetAutonomousDBVersions method from an instance of <see cref="SubscriptionResource"/>.
    /// </summary>
    public partial class AutonomousDBVersionCollection : ArmCollection, IEnumerable<AutonomousDBVersionResource>, IAsyncEnumerable<AutonomousDBVersionResource>
    {
        private readonly ClientDiagnostics _autonomousDBVersionAutonomousDatabaseVersionsClientDiagnostics;
        private readonly AutonomousDatabaseVersionsRestOperations _autonomousDBVersionAutonomousDatabaseVersionsRestClient;
        private readonly AzureLocation _location;

        /// <summary> Initializes a new instance of the <see cref="AutonomousDBVersionCollection"/> class for mocking. </summary>
        protected AutonomousDBVersionCollection()
        {
        }

        /// <summary> Initializes a new instance of the <see cref="AutonomousDBVersionCollection"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="id"> The identifier of the parent resource that is the target of operations. </param>
        /// <param name="location"> The name of the Azure region. </param>
        internal AutonomousDBVersionCollection(ArmClient client, ResourceIdentifier id, AzureLocation location) : base(client, id)
        {
            _location = location;
            _autonomousDBVersionAutonomousDatabaseVersionsClientDiagnostics = new ClientDiagnostics("Azure.ResourceManager.OracleDatabase", AutonomousDBVersionResource.ResourceType.Namespace, Diagnostics);
            TryGetApiVersion(AutonomousDBVersionResource.ResourceType, out string autonomousDBVersionAutonomousDatabaseVersionsApiVersion);
            _autonomousDBVersionAutonomousDatabaseVersionsRestClient = new AutonomousDatabaseVersionsRestOperations(Pipeline, Diagnostics.ApplicationId, Endpoint, autonomousDBVersionAutonomousDatabaseVersionsApiVersion);
#if DEBUG
			ValidateResourceId(Id);
#endif
        }

        internal static void ValidateResourceId(ResourceIdentifier id)
        {
            if (id.ResourceType != SubscriptionResource.ResourceType)
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Invalid resource type {0} expected {1}", id.ResourceType, SubscriptionResource.ResourceType), nameof(id));
        }

        /// <summary>
        /// Get a AutonomousDbVersion
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Oracle.Database/locations/{location}/autonomousDbVersions/{autonomousdbversionsname}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>AutonomousDbVersion_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AutonomousDBVersionResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="autonomousdbversionsname"> AutonomousDbVersion name. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="autonomousdbversionsname"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="autonomousdbversionsname"/> is null. </exception>
        public virtual async Task<Response<AutonomousDBVersionResource>> GetAsync(string autonomousdbversionsname, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(autonomousdbversionsname, nameof(autonomousdbversionsname));

            using var scope = _autonomousDBVersionAutonomousDatabaseVersionsClientDiagnostics.CreateScope("AutonomousDBVersionCollection.Get");
            scope.Start();
            try
            {
                var response = await _autonomousDBVersionAutonomousDatabaseVersionsRestClient.GetAsync(Id.SubscriptionId, new AzureLocation(_location), autonomousdbversionsname, cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new AutonomousDBVersionResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Get a AutonomousDbVersion
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Oracle.Database/locations/{location}/autonomousDbVersions/{autonomousdbversionsname}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>AutonomousDbVersion_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AutonomousDBVersionResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="autonomousdbversionsname"> AutonomousDbVersion name. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="autonomousdbversionsname"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="autonomousdbversionsname"/> is null. </exception>
        public virtual Response<AutonomousDBVersionResource> Get(string autonomousdbversionsname, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(autonomousdbversionsname, nameof(autonomousdbversionsname));

            using var scope = _autonomousDBVersionAutonomousDatabaseVersionsClientDiagnostics.CreateScope("AutonomousDBVersionCollection.Get");
            scope.Start();
            try
            {
                var response = _autonomousDBVersionAutonomousDatabaseVersionsRestClient.Get(Id.SubscriptionId, new AzureLocation(_location), autonomousdbversionsname, cancellationToken);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new AutonomousDBVersionResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// List AutonomousDbVersion resources by SubscriptionLocationResource
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Oracle.Database/locations/{location}/autonomousDbVersions</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>AutonomousDbVersion_ListByLocation</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AutonomousDBVersionResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <returns> An async collection of <see cref="AutonomousDBVersionResource"/> that may take multiple service requests to iterate over. </returns>
        public virtual AsyncPageable<AutonomousDBVersionResource> GetAllAsync(CancellationToken cancellationToken = default)
        {
            HttpMessage FirstPageRequest(int? pageSizeHint) => _autonomousDBVersionAutonomousDatabaseVersionsRestClient.CreateListByLocationRequest(Id.SubscriptionId, new AzureLocation(_location));
            HttpMessage NextPageRequest(int? pageSizeHint, string nextLink) => _autonomousDBVersionAutonomousDatabaseVersionsRestClient.CreateListByLocationNextPageRequest(nextLink, Id.SubscriptionId, new AzureLocation(_location));
            return GeneratorPageableHelpers.CreateAsyncPageable(FirstPageRequest, NextPageRequest, e => new AutonomousDBVersionResource(Client, AutonomousDBVersionData.DeserializeAutonomousDBVersionData(e)), _autonomousDBVersionAutonomousDatabaseVersionsClientDiagnostics, Pipeline, "AutonomousDBVersionCollection.GetAll", "value", "nextLink", cancellationToken);
        }

        /// <summary>
        /// List AutonomousDbVersion resources by SubscriptionLocationResource
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Oracle.Database/locations/{location}/autonomousDbVersions</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>AutonomousDbVersion_ListByLocation</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AutonomousDBVersionResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <returns> A collection of <see cref="AutonomousDBVersionResource"/> that may take multiple service requests to iterate over. </returns>
        public virtual Pageable<AutonomousDBVersionResource> GetAll(CancellationToken cancellationToken = default)
        {
            HttpMessage FirstPageRequest(int? pageSizeHint) => _autonomousDBVersionAutonomousDatabaseVersionsRestClient.CreateListByLocationRequest(Id.SubscriptionId, new AzureLocation(_location));
            HttpMessage NextPageRequest(int? pageSizeHint, string nextLink) => _autonomousDBVersionAutonomousDatabaseVersionsRestClient.CreateListByLocationNextPageRequest(nextLink, Id.SubscriptionId, new AzureLocation(_location));
            return GeneratorPageableHelpers.CreatePageable(FirstPageRequest, NextPageRequest, e => new AutonomousDBVersionResource(Client, AutonomousDBVersionData.DeserializeAutonomousDBVersionData(e)), _autonomousDBVersionAutonomousDatabaseVersionsClientDiagnostics, Pipeline, "AutonomousDBVersionCollection.GetAll", "value", "nextLink", cancellationToken);
        }

        /// <summary>
        /// Checks to see if the resource exists in azure.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Oracle.Database/locations/{location}/autonomousDbVersions/{autonomousdbversionsname}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>AutonomousDbVersion_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AutonomousDBVersionResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="autonomousdbversionsname"> AutonomousDbVersion name. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="autonomousdbversionsname"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="autonomousdbversionsname"/> is null. </exception>
        public virtual async Task<Response<bool>> ExistsAsync(string autonomousdbversionsname, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(autonomousdbversionsname, nameof(autonomousdbversionsname));

            using var scope = _autonomousDBVersionAutonomousDatabaseVersionsClientDiagnostics.CreateScope("AutonomousDBVersionCollection.Exists");
            scope.Start();
            try
            {
                var response = await _autonomousDBVersionAutonomousDatabaseVersionsRestClient.GetAsync(Id.SubscriptionId, new AzureLocation(_location), autonomousdbversionsname, cancellationToken: cancellationToken).ConfigureAwait(false);
                return Response.FromValue(response.Value != null, response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Checks to see if the resource exists in azure.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Oracle.Database/locations/{location}/autonomousDbVersions/{autonomousdbversionsname}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>AutonomousDbVersion_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AutonomousDBVersionResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="autonomousdbversionsname"> AutonomousDbVersion name. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="autonomousdbversionsname"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="autonomousdbversionsname"/> is null. </exception>
        public virtual Response<bool> Exists(string autonomousdbversionsname, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(autonomousdbversionsname, nameof(autonomousdbversionsname));

            using var scope = _autonomousDBVersionAutonomousDatabaseVersionsClientDiagnostics.CreateScope("AutonomousDBVersionCollection.Exists");
            scope.Start();
            try
            {
                var response = _autonomousDBVersionAutonomousDatabaseVersionsRestClient.Get(Id.SubscriptionId, new AzureLocation(_location), autonomousdbversionsname, cancellationToken: cancellationToken);
                return Response.FromValue(response.Value != null, response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Tries to get details for this resource from the service.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Oracle.Database/locations/{location}/autonomousDbVersions/{autonomousdbversionsname}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>AutonomousDbVersion_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AutonomousDBVersionResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="autonomousdbversionsname"> AutonomousDbVersion name. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="autonomousdbversionsname"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="autonomousdbversionsname"/> is null. </exception>
        public virtual async Task<NullableResponse<AutonomousDBVersionResource>> GetIfExistsAsync(string autonomousdbversionsname, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(autonomousdbversionsname, nameof(autonomousdbversionsname));

            using var scope = _autonomousDBVersionAutonomousDatabaseVersionsClientDiagnostics.CreateScope("AutonomousDBVersionCollection.GetIfExists");
            scope.Start();
            try
            {
                var response = await _autonomousDBVersionAutonomousDatabaseVersionsRestClient.GetAsync(Id.SubscriptionId, new AzureLocation(_location), autonomousdbversionsname, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    return new NoValueResponse<AutonomousDBVersionResource>(response.GetRawResponse());
                return Response.FromValue(new AutonomousDBVersionResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Tries to get details for this resource from the service.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Oracle.Database/locations/{location}/autonomousDbVersions/{autonomousdbversionsname}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>AutonomousDbVersion_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AutonomousDBVersionResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="autonomousdbversionsname"> AutonomousDbVersion name. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="autonomousdbversionsname"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="autonomousdbversionsname"/> is null. </exception>
        public virtual NullableResponse<AutonomousDBVersionResource> GetIfExists(string autonomousdbversionsname, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(autonomousdbversionsname, nameof(autonomousdbversionsname));

            using var scope = _autonomousDBVersionAutonomousDatabaseVersionsClientDiagnostics.CreateScope("AutonomousDBVersionCollection.GetIfExists");
            scope.Start();
            try
            {
                var response = _autonomousDBVersionAutonomousDatabaseVersionsRestClient.Get(Id.SubscriptionId, new AzureLocation(_location), autonomousdbversionsname, cancellationToken: cancellationToken);
                if (response.Value == null)
                    return new NoValueResponse<AutonomousDBVersionResource>(response.GetRawResponse());
                return Response.FromValue(new AutonomousDBVersionResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        IEnumerator<AutonomousDBVersionResource> IEnumerable<AutonomousDBVersionResource>.GetEnumerator()
        {
            return GetAll().GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetAll().GetEnumerator();
        }

        IAsyncEnumerator<AutonomousDBVersionResource> IAsyncEnumerable<AutonomousDBVersionResource>.GetAsyncEnumerator(CancellationToken cancellationToken)
        {
            return GetAllAsync(cancellationToken: cancellationToken).GetAsyncEnumerator(cancellationToken);
        }
    }
}
