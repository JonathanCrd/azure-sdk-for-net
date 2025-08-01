// <auto-generated/>

#nullable disable

using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Linq;

namespace Azure.AI.OpenAI
{
    internal static partial class PipelineRequestHeadersExtensions
    {
        /// <param name="headers"></param>
        /// <param name="name"> The name. </param>
        /// <param name="value"> The value. </param>
        /// <param name="delimiter"> The delimiter. </param>
        public static void SetDelimited<T>(this PipelineRequestHeaders headers, string name, IEnumerable<T> value, string delimiter)
        {
            IEnumerable<string> stringValues = value.Select(v => TypeFormatters.ConvertToString(v));
            headers.Set(name, string.Join(delimiter, stringValues));
        }

        /// <param name="headers"></param>
        /// <param name="name"> The name. </param>
        /// <param name="value"> The value. </param>
        /// <param name="delimiter"> The delimiter. </param>
        /// <param name="format"> The format. </param>
        public static void SetDelimited<T>(this PipelineRequestHeaders headers, string name, IEnumerable<T> value, string delimiter, string format)
        {
            IEnumerable<string> stringValues = value.Select(v => TypeFormatters.ConvertToString(v, format));
            headers.Set(name, string.Join(delimiter, stringValues));
        }
    }
}
