using System.IO;
using System.Text;
using System;

namespace ArcTool
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("AIL Archive Tool");
                Console.WriteLine("  created by Crsky");
                Console.WriteLine();
                Console.WriteLine("Usage:");
                Console.WriteLine("  Extract : ArcTool -e -in [input.dat] -out [output]");
                Console.WriteLine("  Create  : ArcTool -c -in [folder] -out [output.dat]");
                Console.WriteLine();
                Console.WriteLine("Press any key to continue...");

                Environment.ExitCode = 1;
                Console.ReadKey();

                return;
            }

            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            var parsedArgs = CommandLineParser.ParseArguments(args);

            CommandLineParser.EnsureArguments(parsedArgs, "-in", "-out");

            var inputPath = Path.GetFullPath(parsedArgs["-in"]);
            var outputPath = Path.GetFullPath(parsedArgs["-out"]);

            if (parsedArgs.ContainsKey("-e"))
            {
                Arc.Extract(inputPath, outputPath);
                return;
            }

            if (parsedArgs.ContainsKey("-c"))
            {
                Arc.Create(inputPath, outputPath);
                return;
            }
        }
    }
}
