using System;
using System.IO;
using System.Text;

namespace ScriptTool
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("AIL Script Tool");
                Console.WriteLine("  created by Crsky");
                Console.WriteLine();
                Console.WriteLine("Usage:");
                Console.WriteLine("  Disassemble : ScriptTool -d -in [input.bin] -icp [shift_jis] -out [output.txt]");
                Console.WriteLine("  Export Text : ScriptTool -e -in [input.bin] -icp [shift_jis] -out [output.txt]");
                Console.WriteLine("  Import Text : ScriptTool -i -in [input.bin] -icp [shift_jis] -out [output.bin] -ocp [shift_jis] -txt [input.txt]");
                Console.WriteLine("  Import Text : ScriptTool -b -in [input.bin] -icp [shift_jis] -out [output.bin] -ocp [shift_jis] -txt [input.txt]");
                Console.WriteLine();
                Console.WriteLine("Note: The [-b] mode mean rebuild full string section.");
                Console.WriteLine("      This mode may cause data errors.");
                Console.WriteLine();
                Console.WriteLine("Press any key to continue...");

                Environment.ExitCode = 1;
                Console.ReadKey();

                return;
            }

            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            var parsedArgs = CommandLineParser.ParseArguments(args);

            // Common arguments
            CommandLineParser.EnsureArguments(parsedArgs, "-in", "-icp", "-out");

            var inputPath = Path.GetFullPath(parsedArgs["-in"]);
            var outputPath = Path.GetFullPath(parsedArgs["-out"]);
            var inputEncoding = Encoding.GetEncoding(parsedArgs["-icp"]);

            // Disassemble
            if (parsedArgs.ContainsKey("-d"))
            {
                var script = new Script();
                script.Load(inputPath, inputEncoding);
                script.ExportDisasm(outputPath);
                return;
            }

            // Export Text
            if (parsedArgs.ContainsKey("-e"))
            {
                var script = new Script();
                script.Load(inputPath, inputEncoding);
                script.ExportText(outputPath);
                return;
            }

            // Import Text
            if (parsedArgs.ContainsKey("-i"))
            {
                CommandLineParser.EnsureArguments(parsedArgs, "-ocp", "-txt");

                var txtPath = Path.GetFullPath(parsedArgs["-txt"]);
                var outputEncoding = Encoding.GetEncoding(parsedArgs["-ocp"]);

                var script = new Script();
                script.Load(inputPath, inputEncoding);
                script.ImportText(txtPath, outputEncoding);
                script.Save(outputPath);

                return;
            }

            // Import Text
            if (parsedArgs.ContainsKey("-b"))
            {
                CommandLineParser.EnsureArguments(parsedArgs, "-ocp", "-txt");

                var txtPath = Path.GetFullPath(parsedArgs["-txt"]);
                var outputEncoding = Encoding.GetEncoding(parsedArgs["-ocp"]);

                var script = new Script();
                script.Load(inputPath, inputEncoding);
                script.ImportTextRebuild(txtPath, outputEncoding);
                script.Save(outputPath);

                return;
            }
        }
    }
}
