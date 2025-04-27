using System.IO;
using System.Text;

namespace ScriptTool
{
    internal static class BinaryWriterExtensions
    {
        public static void WriteNullTerminatedString(this BinaryWriter writer, string s, Encoding encoding)
        {
            var bytes = encoding.GetBytes(s);
            writer.Write(bytes);
            writer.Write((byte)0);
        }
    }
}
