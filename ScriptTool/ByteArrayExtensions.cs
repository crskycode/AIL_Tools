using System.Linq;
using System.Text;

namespace ScriptTool
{
    internal static class ByteArrayExtensions
    {
        public static string ReadNullTerminatedString(this byte[] source, int offset, Encoding encoding)
        {
            var bytes = source.Skip(offset).TakeWhile(x => x != 0).ToArray();

            if (bytes.Length == 0)
            {
                return string.Empty;
            }

            return encoding.GetString(bytes);
        }
    }
}
