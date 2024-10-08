// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;
using System.Linq;

namespace Azure.ResourceManager.SecurityInsights.Models
{
    /// <summary> Represents a single clause to be evaluated by a NormalizedCondition. </summary>
    public partial class ThreatIntelligenceQueryConditionClause
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

        /// <summary> Initializes a new instance of <see cref="ThreatIntelligenceQueryConditionClause"/>. </summary>
        /// <param name="field"> The name of the field that is evaluated. </param>
        /// <param name="operator"> Represents an operator in a ConditionClause. </param>
        /// <param name="values"> The top level connective operator for this condition. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="field"/> or <paramref name="values"/> is null. </exception>
        public ThreatIntelligenceQueryConditionClause(string field, ThreatIntelligenceQueryOperator @operator, IEnumerable<string> values)
        {
            Argument.AssertNotNull(field, nameof(field));
            Argument.AssertNotNull(values, nameof(values));

            Field = field;
            Operator = @operator;
            Values = values.ToList();
        }

        /// <summary> Initializes a new instance of <see cref="ThreatIntelligenceQueryConditionClause"/>. </summary>
        /// <param name="clauseConnective"> The connective used to join all values in this ConditionClause. </param>
        /// <param name="field"> The name of the field that is evaluated. </param>
        /// <param name="operator"> Represents an operator in a ConditionClause. </param>
        /// <param name="values"> The top level connective operator for this condition. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal ThreatIntelligenceQueryConditionClause(ThreatIntelligenceQueryConnective? clauseConnective, string field, ThreatIntelligenceQueryOperator @operator, IList<string> values, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            ClauseConnective = clauseConnective;
            Field = field;
            Operator = @operator;
            Values = values;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> Initializes a new instance of <see cref="ThreatIntelligenceQueryConditionClause"/> for deserialization. </summary>
        internal ThreatIntelligenceQueryConditionClause()
        {
        }

        /// <summary> The connective used to join all values in this ConditionClause. </summary>
        [WirePath("clauseConnective")]
        public ThreatIntelligenceQueryConnective? ClauseConnective { get; set; }
        /// <summary> The name of the field that is evaluated. </summary>
        [WirePath("field")]
        public string Field { get; }
        /// <summary> Represents an operator in a ConditionClause. </summary>
        [WirePath("operator")]
        public ThreatIntelligenceQueryOperator Operator { get; }
        /// <summary> The top level connective operator for this condition. </summary>
        [WirePath("values")]
        public IList<string> Values { get; }
    }
}
