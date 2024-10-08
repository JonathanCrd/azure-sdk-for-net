// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager.AppComplianceAutomation.Models;

namespace Azure.ResourceManager.AppComplianceAutomation
{
    /// <summary>
    /// A Class representing an AppComplianceReportWebhook along with the instance operations that can be performed on it.
    /// If you have a <see cref="ResourceIdentifier"/> you can construct an <see cref="AppComplianceReportWebhookResource"/>
    /// from an instance of <see cref="ArmClient"/> using the GetAppComplianceReportWebhookResource method.
    /// Otherwise you can get one from its parent resource <see cref="AppComplianceReportResource"/> using the GetAppComplianceReportWebhook method.
    /// </summary>
    public partial class AppComplianceReportWebhookResource : ArmResource
    {
        /// <summary> Generate the resource identifier of a <see cref="AppComplianceReportWebhookResource"/> instance. </summary>
        /// <param name="reportName"> The reportName. </param>
        /// <param name="webhookName"> The webhookName. </param>
        public static ResourceIdentifier CreateResourceIdentifier(string reportName, string webhookName)
        {
            var resourceId = $"/providers/Microsoft.AppComplianceAutomation/reports/{reportName}/webhooks/{webhookName}";
            return new ResourceIdentifier(resourceId);
        }

        private readonly ClientDiagnostics _appComplianceReportWebhookWebhookClientDiagnostics;
        private readonly WebhookRestOperations _appComplianceReportWebhookWebhookRestClient;
        private readonly AppComplianceReportWebhookData _data;

        /// <summary> Gets the resource type for the operations. </summary>
        public static readonly ResourceType ResourceType = "Microsoft.AppComplianceAutomation/reports/webhooks";

        /// <summary> Initializes a new instance of the <see cref="AppComplianceReportWebhookResource"/> class for mocking. </summary>
        protected AppComplianceReportWebhookResource()
        {
        }

        /// <summary> Initializes a new instance of the <see cref="AppComplianceReportWebhookResource"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="data"> The resource that is the target of operations. </param>
        internal AppComplianceReportWebhookResource(ArmClient client, AppComplianceReportWebhookData data) : this(client, data.Id)
        {
            HasData = true;
            _data = data;
        }

        /// <summary> Initializes a new instance of the <see cref="AppComplianceReportWebhookResource"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="id"> The identifier of the resource that is the target of operations. </param>
        internal AppComplianceReportWebhookResource(ArmClient client, ResourceIdentifier id) : base(client, id)
        {
            _appComplianceReportWebhookWebhookClientDiagnostics = new ClientDiagnostics("Azure.ResourceManager.AppComplianceAutomation", ResourceType.Namespace, Diagnostics);
            TryGetApiVersion(ResourceType, out string appComplianceReportWebhookWebhookApiVersion);
            _appComplianceReportWebhookWebhookRestClient = new WebhookRestOperations(Pipeline, Diagnostics.ApplicationId, Endpoint, appComplianceReportWebhookWebhookApiVersion);
#if DEBUG
			ValidateResourceId(Id);
#endif
        }

        /// <summary> Gets whether or not the current instance has data. </summary>
        public virtual bool HasData { get; }

        /// <summary> Gets the data representing this Feature. </summary>
        /// <exception cref="InvalidOperationException"> Throws if there is no data loaded in the current instance. </exception>
        public virtual AppComplianceReportWebhookData Data
        {
            get
            {
                if (!HasData)
                    throw new InvalidOperationException("The current instance does not have data, you must call Get first.");
                return _data;
            }
        }

        internal static void ValidateResourceId(ResourceIdentifier id)
        {
            if (id.ResourceType != ResourceType)
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Invalid resource type {0} expected {1}", id.ResourceType, ResourceType), nameof(id));
        }

        /// <summary>
        /// Get the AppComplianceAutomation webhook and its properties.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/providers/Microsoft.AppComplianceAutomation/reports/{reportName}/webhooks/{webhookName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Webhook_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-06-27</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AppComplianceReportWebhookResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        public virtual async Task<Response<AppComplianceReportWebhookResource>> GetAsync(CancellationToken cancellationToken = default)
        {
            using var scope = _appComplianceReportWebhookWebhookClientDiagnostics.CreateScope("AppComplianceReportWebhookResource.Get");
            scope.Start();
            try
            {
                var response = await _appComplianceReportWebhookWebhookRestClient.GetAsync(Id.Parent.Name, Id.Name, cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new AppComplianceReportWebhookResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Get the AppComplianceAutomation webhook and its properties.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/providers/Microsoft.AppComplianceAutomation/reports/{reportName}/webhooks/{webhookName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Webhook_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-06-27</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AppComplianceReportWebhookResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        public virtual Response<AppComplianceReportWebhookResource> Get(CancellationToken cancellationToken = default)
        {
            using var scope = _appComplianceReportWebhookWebhookClientDiagnostics.CreateScope("AppComplianceReportWebhookResource.Get");
            scope.Start();
            try
            {
                var response = _appComplianceReportWebhookWebhookRestClient.Get(Id.Parent.Name, Id.Name, cancellationToken);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new AppComplianceReportWebhookResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Delete an AppComplianceAutomation webhook.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/providers/Microsoft.AppComplianceAutomation/reports/{reportName}/webhooks/{webhookName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Webhook_Delete</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-06-27</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AppComplianceReportWebhookResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="waitUntil"> <see cref="WaitUntil.Completed"/> if the method should wait to return until the long-running operation has completed on the service; <see cref="WaitUntil.Started"/> if it should return after starting the operation. For more information on long-running operations, please see <see href="https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/samples/LongRunningOperations.md"> Azure.Core Long-Running Operation samples</see>. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        public virtual async Task<ArmOperation> DeleteAsync(WaitUntil waitUntil, CancellationToken cancellationToken = default)
        {
            using var scope = _appComplianceReportWebhookWebhookClientDiagnostics.CreateScope("AppComplianceReportWebhookResource.Delete");
            scope.Start();
            try
            {
                var response = await _appComplianceReportWebhookWebhookRestClient.DeleteAsync(Id.Parent.Name, Id.Name, cancellationToken).ConfigureAwait(false);
                var uri = _appComplianceReportWebhookWebhookRestClient.CreateDeleteRequestUri(Id.Parent.Name, Id.Name);
                var rehydrationToken = NextLinkOperationImplementation.GetRehydrationToken(RequestMethod.Delete, uri.ToUri(), uri.ToString(), "None", null, OperationFinalStateVia.OriginalUri.ToString());
                var operation = new AppComplianceAutomationArmOperation(response, rehydrationToken);
                if (waitUntil == WaitUntil.Completed)
                    await operation.WaitForCompletionResponseAsync(cancellationToken).ConfigureAwait(false);
                return operation;
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Delete an AppComplianceAutomation webhook.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/providers/Microsoft.AppComplianceAutomation/reports/{reportName}/webhooks/{webhookName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Webhook_Delete</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-06-27</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AppComplianceReportWebhookResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="waitUntil"> <see cref="WaitUntil.Completed"/> if the method should wait to return until the long-running operation has completed on the service; <see cref="WaitUntil.Started"/> if it should return after starting the operation. For more information on long-running operations, please see <see href="https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/samples/LongRunningOperations.md"> Azure.Core Long-Running Operation samples</see>. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        public virtual ArmOperation Delete(WaitUntil waitUntil, CancellationToken cancellationToken = default)
        {
            using var scope = _appComplianceReportWebhookWebhookClientDiagnostics.CreateScope("AppComplianceReportWebhookResource.Delete");
            scope.Start();
            try
            {
                var response = _appComplianceReportWebhookWebhookRestClient.Delete(Id.Parent.Name, Id.Name, cancellationToken);
                var uri = _appComplianceReportWebhookWebhookRestClient.CreateDeleteRequestUri(Id.Parent.Name, Id.Name);
                var rehydrationToken = NextLinkOperationImplementation.GetRehydrationToken(RequestMethod.Delete, uri.ToUri(), uri.ToString(), "None", null, OperationFinalStateVia.OriginalUri.ToString());
                var operation = new AppComplianceAutomationArmOperation(response, rehydrationToken);
                if (waitUntil == WaitUntil.Completed)
                    operation.WaitForCompletionResponse(cancellationToken);
                return operation;
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Update an exiting AppComplianceAutomation webhook.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/providers/Microsoft.AppComplianceAutomation/reports/{reportName}/webhooks/{webhookName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Webhook_Update</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-06-27</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AppComplianceReportWebhookResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="patch"> Parameters for the create or update operation. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="patch"/> is null. </exception>
        public virtual async Task<Response<AppComplianceReportWebhookResource>> UpdateAsync(AppComplianceReportWebhookPatch patch, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNull(patch, nameof(patch));

            using var scope = _appComplianceReportWebhookWebhookClientDiagnostics.CreateScope("AppComplianceReportWebhookResource.Update");
            scope.Start();
            try
            {
                var response = await _appComplianceReportWebhookWebhookRestClient.UpdateAsync(Id.Parent.Name, Id.Name, patch, cancellationToken).ConfigureAwait(false);
                return Response.FromValue(new AppComplianceReportWebhookResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Update an exiting AppComplianceAutomation webhook.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/providers/Microsoft.AppComplianceAutomation/reports/{reportName}/webhooks/{webhookName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Webhook_Update</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-06-27</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="AppComplianceReportWebhookResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="patch"> Parameters for the create or update operation. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="patch"/> is null. </exception>
        public virtual Response<AppComplianceReportWebhookResource> Update(AppComplianceReportWebhookPatch patch, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNull(patch, nameof(patch));

            using var scope = _appComplianceReportWebhookWebhookClientDiagnostics.CreateScope("AppComplianceReportWebhookResource.Update");
            scope.Start();
            try
            {
                var response = _appComplianceReportWebhookWebhookRestClient.Update(Id.Parent.Name, Id.Name, patch, cancellationToken);
                return Response.FromValue(new AppComplianceReportWebhookResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }
    }
}
