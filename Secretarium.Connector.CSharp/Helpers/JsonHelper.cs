using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

namespace Secretarium.Client.Helpers
{
    public static class JsonHelper
    {
        private static readonly JsonSerializerSettings _jsonSecretariumFormatSettings;
        private static readonly JsonSerializerSettings _jsonSecretariumSettings;

        static JsonHelper()
        {
            _jsonSecretariumFormatSettings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                NullValueHandling = NullValueHandling.Ignore
            };

            _jsonSecretariumSettings = new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore
            };
        }

        public static string ToJson<T>(this T o, bool formatted = false)
        {
            return JsonConvert.SerializeObject(o, formatted ? _jsonSecretariumFormatSettings : _jsonSecretariumSettings);
        }

        public static string ToJson(this JToken o, bool formatted = false)
        {
            return o.ToString(formatted ? Formatting.Indented : Formatting.None);
        }

        public static T DeserializeJsonAs<T>(this byte[] message)
        {
            return message.GetUtf8String().DeserializeJsonAs<T>();
        }

        public static T DeserializeJsonAs<T>(this string message)
        {
            return JsonConvert.DeserializeObject<T>(message);
        }

        public static bool TryDeserializeJsonAs<T>(this string message, out T o)
        {
            try
            {
                o = JsonConvert.DeserializeObject<T>(message);
                return true;
            }
            catch (Exception)
            {
                o = default(T);
                return false;
            }
        }

        public static T DeserializeJsonFromFileAs<T>(string fullPath)
        {
            using (var sr = new StreamReader(fullPath))
            {
                var json = sr.ReadToEnd();
                return JsonConvert.DeserializeObject<T>(json);
            }
        }
    }
}