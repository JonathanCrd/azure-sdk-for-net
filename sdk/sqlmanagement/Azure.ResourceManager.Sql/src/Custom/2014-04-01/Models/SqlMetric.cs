﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable disable

using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace Azure.ResourceManager.Sql.Models
{
    /// <summary> Database metrics. </summary>
    [Obsolete("This class is deprecated and will be removed in a future release.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public partial class SqlMetric
    {
        /// <summary>
        /// Keeps track of any properties unknown to the library.
        /// <para>
        /// To assign an object to the value of this property use <see cref="BinaryData.FromObjectAsJson{T}(T, System.Text.Json.JsonSerializerOptions?)"/>.
        /// </para>
        /// <para>
        /// To assign an already formatted json string to this property use <see cref="BinaryData.FromString(string)"/>.
        /// </para>
        /// <para>
        /// Examples:
        /// <list type="bullet">
        /// <item>
        /// <term>BinaryData.FromObjectAsJson("foo")</term>
        /// <description>Creates a payload of "foo".</description>
        /// </item>
        /// <item>
        /// <term>BinaryData.FromString("\"foo\"")</term>
        /// <description>Creates a payload of "foo".</description>
        /// </item>
        /// <item>
        /// <term>BinaryData.FromObjectAsJson(new { key = "value" })</term>
        /// <description>Creates a payload of { "key": "value" }.</description>
        /// </item>
        /// <item>
        /// <term>BinaryData.FromString("{\"key\": \"value\"}")</term>
        /// <description>Creates a payload of { "key": "value" }.</description>
        /// </item>
        /// </list>
        /// </para>
        /// </summary>
        private IDictionary<string, BinaryData> _serializedAdditionalRawData;

        /// <summary> Initializes a new instance of <see cref="SqlMetric"/>. </summary>
        internal SqlMetric()
        {
            MetricValues = new ChangeTrackingList<SqlMetricValue>();
        }

        /// <summary> Initializes a new instance of <see cref="SqlMetric"/>. </summary>
        /// <param name="startOn"> The start time for the metric (ISO-8601 format). </param>
        /// <param name="endOn"> The end time for the metric (ISO-8601 format). </param>
        /// <param name="timeGrain"> The time step to be used to summarize the metric values. </param>
        /// <param name="unit"> The unit of the metric. </param>
        /// <param name="name"> The name information for the metric. </param>
        /// <param name="metricValues"> The metric values for the specified time window and timestep. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal SqlMetric(DateTimeOffset? startOn, DateTimeOffset? endOn, string timeGrain, SqlMetricUnitType? unit, SqlMetricName name, IReadOnlyList<SqlMetricValue> metricValues, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            StartOn = startOn;
            EndOn = endOn;
            TimeGrain = timeGrain;
            Unit = unit;
            Name = name;
            MetricValues = metricValues;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> The start time for the metric (ISO-8601 format). </summary>
        [WirePath("startTime")]
        public DateTimeOffset? StartOn { get; }
        /// <summary> The end time for the metric (ISO-8601 format). </summary>
        [WirePath("endTime")]
        public DateTimeOffset? EndOn { get; }
        /// <summary> The time step to be used to summarize the metric values. </summary>
        [WirePath("timeGrain")]
        public string TimeGrain { get; }
        /// <summary> The unit of the metric. </summary>
        [WirePath("unit")]
        public SqlMetricUnitType? Unit { get; }
        /// <summary> The name information for the metric. </summary>
        [WirePath("name")]
        public SqlMetricName Name { get; }
        /// <summary> The metric values for the specified time window and timestep. </summary>
        [WirePath("metricValues")]
        public IReadOnlyList<SqlMetricValue> MetricValues { get; }
    }
}
