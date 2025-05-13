using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace ArcTool
{
    internal partial class Arc
    {
        public static void Extract(string filePath, string outputPath)
        {
            using var reader = new BinaryReader(File.OpenRead(filePath));

            var count = reader.ReadInt32();

            var entryLength = new List<int>();

            for (var i = 0; i < count; i++)
            {
                entryLength.Add(reader.ReadInt32());
            }

            Directory.CreateDirectory(outputPath);

            var baseName = Path.GetFileNameWithoutExtension(filePath);

            for (var i = 0; i < count; i++)
            {
                Console.WriteLine($"Extract {i + 1}/{count}");

                var path = Path.Combine(outputPath, i.ToString("D5"));

                if (entryLength[i] == 0)
                {
                    File.WriteAllBytes(path, []);
                    continue;
                }

                var data = reader.ReadBytes(entryLength[i]);

                var isCompressed = (data[0] & 1) != 0;

                if (isCompressed)
                {
                    var lz = new LZSS();
                    data = lz.Decompress(data, 6, data.Length - 6);
                }
                else
                {
                    data = data.Skip(6).ToArray();
                }

                File.WriteAllBytes(path, data);
            }

            reader.Close();
        }

        public static void Create(string rootPath, string filePath)
        {
            // Find files to pack
            var files = Directory.GetFiles(rootPath, "*", SearchOption.TopDirectoryOnly);

            // We only want files whose names contain only numbers
            files = files.Where(x => NumRegex().IsMatch(Path.GetFileName(x)))
                .OrderBy(x => x)
                .ToArray();

            if (files.Length == 0)
            {
                throw new Exception("No files were found to pack.");
            }

            // Get the maximum sequence number in file name
            var num = int.Parse(Path.GetFileName(files.Last()));

            // Check the file sequence to ensure that each file exists
            for (var i = 0; i <= num; i++)
            {
                var path = Path.Combine(rootPath, i.ToString("D5"));

                if (!File.Exists(path))
                {
                    throw new Exception($"Missing file \"{i:D5}\" in directory \"{rootPath}\"");
                }
            }

            // Create new file

            using var writer = new BinaryWriter(File.Create(filePath));

            // Write count
            writer.Write(files.Length);

            // Reserve space for length list
            writer.BaseStream.Position += 4 * files.Length;

            // Add files and create length list

            var lengthList = new List<int>();

            for (var i = 0; i < files.Length; i++)
            {
                Console.WriteLine($"Add {files[i]}");

                var data = File.ReadAllBytes(files[i]);

                // Handle empty file
                if (data.Length == 0)
                {
                    lengthList.Add(0);
                    continue;
                }

                ushort flags = 0;
                var originalLength = data.Length;

                // Detect file types, do not perform compression for certain types
                var doCompress = true;

                if (data.Length >= 4)
                {
                    doCompress = BitConverter.ToUInt32(data) switch
                    {
                        0x474E5089 => false, // PNG
                        0x5367674F => false, // OGG
                        _ => true,
                    };
                }

                if (doCompress)
                {
                    var lz = new LZSS();
                    data = lz.Compress(data, 0, data.Length);

                    flags |= 1;
                }

                // Flags + Length + Data
                var entryLength = 2 + 4 + data.Length;

                // Write entry data
                writer.Write(flags);
                writer.Write(originalLength);
                writer.Write(data);

                lengthList.Add(entryLength);
            }

            // Write length list

            writer.BaseStream.Position = 4;

            for (var i = 0; i < lengthList.Count; i++)
            {
                writer.Write(lengthList[i]);
            }

            // Finished

            writer.Flush();
            writer.Close();

            Console.WriteLine($"Finished");
        }

        [GeneratedRegex("^\\d{5}$")]
        private static partial Regex NumRegex();
    }
}
