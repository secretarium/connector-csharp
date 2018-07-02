namespace Secretarium.Client.Test
{
    public class DCAppForTesting
    {
        public class TextReplaceArgs
        {
            public string Value { get; set; }
            public string FindValue { get; set; }
            public string ReplaceWith { get; set; }
        }

        public static string Conversation(string question)
        {
            var response = "I don't know. I am actually very limited";

            switch (question.ToLower().Replace("?", "").Trim())
            {
                case "how are you":
                    response = "How are you ?";
                    break;
                case "what is the answer to the ultimate question of life, the universe, and everything":
                    response = "42";
                    break;
            }

            return response;
        }

        public static string TextReplace(TextReplaceArgs args)
        {
            return args.Value.Replace(args.FindValue, args.ReplaceWith);
        }

        public static double Sum(double[] numbers)
        {
            var result = 0d;
            foreach (var d in numbers)
            {
                result += d;
            }

            return result;
        }

        public static double Avg(double[] numbers)
        {
            var result = 0d;
            foreach (var d in numbers)
            {
                result += d;
            }

            var length = numbers.Length == 0 ? 1 : numbers.Length;

            return result / length;
        }
    }
}
