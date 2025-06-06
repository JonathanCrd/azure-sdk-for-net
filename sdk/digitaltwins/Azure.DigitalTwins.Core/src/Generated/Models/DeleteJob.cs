// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;

namespace Azure.DigitalTwins.Core.Models
{
    /// <summary> A job which contains a reference to the operations to perform, results, and execution metadata. </summary>
    public partial class DeleteJob
    {
        /// <summary> Initializes a new instance of <see cref="DeleteJob"/>. </summary>
        internal DeleteJob()
        {
        }

        /// <summary> Initializes a new instance of <see cref="DeleteJob"/>. </summary>
        /// <param name="id"> The identifier of the delete job. </param>
        /// <param name="status"> Status of the job. </param>
        /// <param name="createdDateTime"> Start time of the job. The timestamp is in RFC3339 format: `yyyy-MM-ddTHH:mm:ssZ`. </param>
        /// <param name="finishedDateTime"> End time of the job. The timestamp is in RFC3339 format: `yyyy-MM-ddTHH:mm:ssZ`. </param>
        /// <param name="purgeDateTime"> Time at which job will be purged by the service from the system. The timestamp is in RFC3339 format: `yyyy-MM-ddTHH:mm:ssZ`. </param>
        /// <param name="error"> Details of the error(s) that occurred executing the import job. </param>
        internal DeleteJob(string id, DeleteJobStatus? status, DateTimeOffset? createdDateTime, DateTimeOffset? finishedDateTime, DateTimeOffset? purgeDateTime, ErrorInformation error)
        {
            Id = id;
            Status = status;
            CreatedDateTime = createdDateTime;
            FinishedDateTime = finishedDateTime;
            PurgeDateTime = purgeDateTime;
            Error = error;
        }

        /// <summary> The identifier of the delete job. </summary>
        public string Id { get; }
        /// <summary> Status of the job. </summary>
        public DeleteJobStatus? Status { get; }
        /// <summary> Start time of the job. The timestamp is in RFC3339 format: `yyyy-MM-ddTHH:mm:ssZ`. </summary>
        public DateTimeOffset? CreatedDateTime { get; }
        /// <summary> End time of the job. The timestamp is in RFC3339 format: `yyyy-MM-ddTHH:mm:ssZ`. </summary>
        public DateTimeOffset? FinishedDateTime { get; }
        /// <summary> Time at which job will be purged by the service from the system. The timestamp is in RFC3339 format: `yyyy-MM-ddTHH:mm:ssZ`. </summary>
        public DateTimeOffset? PurgeDateTime { get; }
        /// <summary> Details of the error(s) that occurred executing the import job. </summary>
        public ErrorInformation Error { get; }
    }
}
