// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;

namespace Azure.ResourceManager.DataMigration.Models
{
    /// <summary> The MigrateSqlServerSqlMITaskOutputLoginLevel. </summary>
    public partial class MigrateSqlServerSqlMITaskOutputLoginLevel : MigrateSqlServerSqlMITaskOutput
    {
        /// <summary> Initializes a new instance of <see cref="MigrateSqlServerSqlMITaskOutputLoginLevel"/>. </summary>
        internal MigrateSqlServerSqlMITaskOutputLoginLevel()
        {
            ExceptionsAndWarnings = new ChangeTrackingList<DataMigrationReportableException>();
            ResultType = "LoginLevelOutput";
        }

        /// <summary> Initializes a new instance of <see cref="MigrateSqlServerSqlMITaskOutputLoginLevel"/>. </summary>
        /// <param name="id"> Result identifier. </param>
        /// <param name="resultType"> Result type. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        /// <param name="loginName"> Login name. </param>
        /// <param name="state"> Current state of login. </param>
        /// <param name="stage"> Current stage of login. </param>
        /// <param name="startedOn"> Login migration start time. </param>
        /// <param name="endedOn"> Login migration end time. </param>
        /// <param name="message"> Login migration progress message. </param>
        /// <param name="exceptionsAndWarnings"> Login migration errors and warnings per login. </param>
        internal MigrateSqlServerSqlMITaskOutputLoginLevel(string id, string resultType, IDictionary<string, BinaryData> serializedAdditionalRawData, string loginName, DataMigrationState? state, LoginMigrationStage? stage, DateTimeOffset? startedOn, DateTimeOffset? endedOn, string message, IReadOnlyList<DataMigrationReportableException> exceptionsAndWarnings) : base(id, resultType, serializedAdditionalRawData)
        {
            LoginName = loginName;
            State = state;
            Stage = stage;
            StartedOn = startedOn;
            EndedOn = endedOn;
            Message = message;
            ExceptionsAndWarnings = exceptionsAndWarnings;
            ResultType = resultType ?? "LoginLevelOutput";
        }

        /// <summary> Login name. </summary>
        public string LoginName { get; }
        /// <summary> Current state of login. </summary>
        public DataMigrationState? State { get; }
        /// <summary> Current stage of login. </summary>
        public LoginMigrationStage? Stage { get; }
        /// <summary> Login migration start time. </summary>
        public DateTimeOffset? StartedOn { get; }
        /// <summary> Login migration end time. </summary>
        public DateTimeOffset? EndedOn { get; }
        /// <summary> Login migration progress message. </summary>
        public string Message { get; }
        /// <summary> Login migration errors and warnings per login. </summary>
        public IReadOnlyList<DataMigrationReportableException> ExceptionsAndWarnings { get; }
    }
}
