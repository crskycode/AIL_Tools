using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ScriptTool
{
    internal class Script
    {
        private Encoding _encoding = Encoding.UTF8;
        private int _version = 0;
        private byte[] _header = [];
        private List<Tuple<int, int>> _labels = [];
        private int _codePos = 0;
        private byte[] _codeBuffer = [];
        private byte[] _stringPool = [];

        // If this is not null, the disassembly analysis result is written to it.
        private StringBuilder? Dis = null;
        private string _disassembly = string.Empty;

        // The code addresses that references the strings.
        private List<int> _stringRef = [];

        public void Load(string filePath, Encoding encoding, int version)
        {
            using var reader = new BinaryReader(File.OpenRead(filePath));

            _version = version;
            _header = reader.ReadBytes(12);

            var signature = BitConverter.ToInt32(_header, 0);
            var labelLength = BitConverter.ToUInt16(_header, 4);
            var codeLength = BitConverter.ToUInt16(_header, 6);

            if (signature != 0)
            {
                throw new Exception("This may not be a valid AIL script file.");
            }

            // Read label section

            _labels = [];

            var labelCount = labelLength / 4;

            for (var i = 0; i < labelCount; i++)
            {
                int v1 = reader.ReadUInt16();
                int v2 = reader.ReadUInt16();

                _labels.Add(Tuple.Create(v1, v2));
            }

            // Read code section

            _codePos = Convert.ToInt32(reader.BaseStream.Position);
            _codeBuffer = reader.ReadBytes(codeLength);

            // Read string pool section

            var stringPoolLength = Convert.ToInt32(reader.BaseStream.Length - reader.BaseStream.Position);
            _stringPool = reader.ReadBytes(stringPoolLength);

            reader.Close();

            // Set encoding for strings

            _encoding = encoding;

            // Start parsing the code

            Dis = new StringBuilder(0x400000);
            _stringRef = [];

            ParseCode();

            _disassembly = Dis.ToString();
        }

        public void Save(string filePath)
        {
            if (_header.Length == 0)
            {
                throw new InvalidOperationException();
            }

            using var writer = new BinaryWriter(File.Create(filePath));

            writer.Write(_header);

            foreach (var label in _labels)
            {
                writer.Write(Convert.ToUInt16(label.Item1));
                writer.Write(Convert.ToUInt16(label.Item2));
            }

            writer.Write(_codeBuffer);

            writer.Write(_stringPool);

            writer.Flush();
            writer.Close();
        }

        private void ParseCode()
        {
            var reader = new BinaryReader(new MemoryStream(_codeBuffer));

            while (reader.BaseStream.Position < reader.BaseStream.Length)
            {
                var addr = _codePos + Convert.ToInt32(reader.BaseStream.Position);
                var code = reader.ReadByte();

                // TODO: 

                if (reader.BaseStream.Length - reader.BaseStream.Position < 4)
                {
                    var savePos = reader.BaseStream.Position;

                    for (var j = 0; j < 3; j++)
                    {
                        if (reader.BaseStream.Position == reader.BaseStream.Length)
                        {
                            break;
                        }

                        var b = reader.ReadByte();

                        if (b != 0)
                        {
                            reader.BaseStream.Position = savePos;
                            break;
                        }
                    }
                }

                if (reader.BaseStream.Position == reader.BaseStream.Length)
                {
                    break;
                }

                switch (code)
                {
                    case 0x00:
                    {
                        Dis?.AppendLine($"{addr:X8} | exec_func");
                        if (_version == 1)
                            ParseFunctionV1(reader);
                        else if (_version == 2)
                            ParseFunctionV2(reader);
                        else
                            ParseFunction(reader);
                        break;
                    }
                    case 0x04:
                    {
                        Dis?.AppendLine($"{addr:X8} | store_v");
                        var reg = reader.ReadByte();
                        var mask = reader.ReadUInt16();
                        Dis?.AppendLine($"{addr:X8} | ; reg 0x{reg:X2} 0x{mask:X2}");
                        ParseExpression(reader); // value
                        break;
                    }
                    case 0x05:
                    {
                        Dis?.AppendLine($"{addr:X8} | store_f");
                        var reg = reader.ReadByte();
                        var mask = reader.ReadUInt16();
                        Dis?.AppendLine($"{addr:X8} | ; reg 0x{reg:X2} 0x{mask:X2}");
                        if (_version == 1)
                            ParseFunctionV1(reader);
                        else if (_version == 2)
                            ParseFunctionV2(reader); // value
                        else
                            ParseFunction(reader);
                        break;
                    }
                    case 0x08:
                    {
                        var target = reader.ReadUInt16();
                        Dis?.AppendLine($"{addr:X8} | jump L_{target:X4}");
                        break;
                    }
                    case 0x09:
                    {
                        Dis?.AppendLine($"{addr:X8} | switch");
                        var reg = reader.ReadByte();
                        var mask = reader.ReadUInt16();
                        Dis?.AppendLine($"{addr:X8} | ; reg 0x{reg:X2} 0x{mask:X2}");
                        var defAddr = reader.ReadUInt16();
                        Dis?.AppendLine($"{addr:X8} | ; def L_{defAddr:X8}");
                        var count = reader.ReadByte();
                        Dis?.AppendLine($"{addr:X8} | ; count {count}");
                        for (var i = 0; i < count; i++)
                        {
                            var branchId = reader.ReadByte();
                            var branchAddr = reader.ReadUInt16();
                            Dis?.AppendLine($"{addr:X8} | ; case 0x{branchId:X2} L_{branchAddr:X8}");
                        }
                        break;
                    }
                    case 0x0A:
                    {
                        Dis?.AppendLine($"{addr:X8} | load_script");
                        ParseExpression(reader); // script id
                        break;
                    }
                    case 0x0B:
                    {
                        Dis?.AppendLine($"{addr:X8} | call");
                        ParseExpression(reader); // label
                        ParseExpression(reader); // ?
                        break;
                    }
                    case 0x0C:
                    {
                        Dis?.AppendLine($"{addr:X8} | jump_label");
                        ParseExpression(reader); // label
                        break;
                    }
                    case 0x0D:
                    {
                        Dis?.AppendLine($"{addr:X8} | ret");
                        break;
                    }
                    case 0x10:
                    {
                        Dis?.AppendLine($"{addr:X8} | call_script");
                        ParseExpression(reader); // script id
                        ParseExpression(reader); // label
                        ParseExpression(reader); // ?
                        break;
                    }
                    case 0x11:
                    {
                        Dis?.AppendLine($"{addr:X8} | opcode_{code:X2}");
                        break;
                    }
                    case 0x12:
                    {
                        Dis?.AppendLine($"{addr:X8} | jump_true");
                        ParseExpression(reader); // flag
                        var target = reader.ReadUInt16();
                        Dis?.AppendLine($"{addr:X8} | ; target L_{target:X8}");
                        break;
                    }
                    default:
                    {
                        throw new Exception($"Unexpected opcode {code:X2} at {addr:X8} .");
                    }
                }
            }
        }

        private void ParseFunction(BinaryReader reader)
        {
            var addr = _codePos + Convert.ToInt32(reader.BaseStream.Position);
            var code = reader.ReadByte();

            switch (code)
            {
                case 0x00:
                {
                    Dis?.AppendLine($"{addr:X8} | push string");
                    Dis?.AppendLine($"{addr:X8} | ; type 0");
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x01:
                {
                    Dis?.AppendLine($"{addr:X8} | push string");
                    Dis?.AppendLine($"{addr:X8} | ; type 1");
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x02:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x03:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x04:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x05:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x06:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x07:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x08:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x09:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x0A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x0B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x0C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x10:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x11:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x12:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x13:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x14:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x15:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x16:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x17:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x18:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x19:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x1A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    break;
                }
                case 0x1B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    break;
                }
                case 0x1C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    ParseExpression(reader); // 11
                    break;
                }
                case 0x1D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x1E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x1F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x20:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x21:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x22:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x23:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x24:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x25:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x26:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x27:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x28:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x29:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    break;
                }
                case 0x2A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x2B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x2C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x2D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x2E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x2F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x30:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x31:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x32:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x33:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x34:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x35:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x36:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x37:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x38:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x39:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x3A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x3B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x3C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x3D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x3E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x3F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x40:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x41:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x42:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x43:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x44:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x45:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x46:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x47:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x48:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x49:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x4A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x4B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x4C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x4D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x4E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x4F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x50:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x51:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    break;
                }
                case 0x52:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x53:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x54:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x55:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x56:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x57:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x58:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x59:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x5A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x5B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x5C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x5D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x5E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x5F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x60:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x61:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x62:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x63:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x64:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x65:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x66:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x67:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x68:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x69:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x6A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x6B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x6C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x6D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    ParseExpression(reader); // 11
                    break;
                }
                case 0x6E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x6F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x70:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x71:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x72:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x73:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x74:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x75:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x76:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x77:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x78:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x79:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x7A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x7B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x7C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x7E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x7F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x80:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x81:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x82:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x83:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x84:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x85:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x86:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x87:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x88:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x89:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x8A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x8B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x8C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x8D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x8E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x8F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x90:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x91:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x92:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x93:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x94:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x95:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x96:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x97:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x98:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x99:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x9A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x9B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x9C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x9D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x9E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x9F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0xA0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0xA1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xA2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xA3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xA4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xA5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xA6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xA7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xA8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xA9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xAA:
                {
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    break;
                }
                case 0xAB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xAC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xAD:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xAE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xAF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xB0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xB1:
                {
                    Dis?.AppendLine($"{addr:X8} | setup_window");
                    break;
                }
                case 0xB2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xB3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xB4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    break;
                }
                case 0xB5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xB6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xB7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0xB8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0xB9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xBB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBD:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0xC0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xC1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xC2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xC3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xC8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    break;
                }
                case 0xCA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xCB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xCC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xCD:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xCE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    break;
                }
                case 0xCF:
                {
                    // 既読情報を初期化する
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xD0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xD1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    ParseExpression(reader); // 11
                    break;
                }
                case 0xD2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xD3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    break;
                }
                case 0xD4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xD5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xD6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xD7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0xD8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xD9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xDA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xDB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xDC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xDD:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0xDE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xDF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xE0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xE1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xE2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xE3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xE4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xE5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xE6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xE7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xE8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xE9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xEA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xEB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xEC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xED:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    break;
                }
                case 0xEE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xEF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    break;
                }
                case 0xF0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    break;
                }
                case 0xF2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xF5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0xF6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xFA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xFB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xFC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                default:
                {
                    throw new Exception($"Unexpected function code {code:X2} at {addr:X8} .");
                }
            }
        }

        private void ParseFunctionV1(BinaryReader reader)
        {
            var addr = _codePos + Convert.ToInt32(reader.BaseStream.Position);
            var code = reader.ReadByte();

            switch (code)
            {
                case 0x00:
                {
                    Dis?.AppendLine($"{addr:X8} | push string");
                    Dis?.AppendLine($"{addr:X8} | ; type 0");
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x01:
                {
                    Dis?.AppendLine($"{addr:X8} | push string");
                    Dis?.AppendLine($"{addr:X8} | ; type 1");
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x02:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x03:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x04:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x05:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x06:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x07:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x08:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x09:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x0A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x0B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x0C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x10:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x11:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x12:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x13:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x14:
                case 0x54:
                case 0x5C:
                case 0x75:
                case 0x7B:
                case 0x7C:
                case 0xA3:
                case 0xA7:
                case 0xB1:
                case 0xDA:
                case 0xDB:
                case 0xDC:
                case 0xE6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x15:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x16:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x17:
                case 0x18:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x19:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x1A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    break;
                }
                case 0x1B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    break;
                }
                case 0x1C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    ParseExpression(reader); // 11
                    break;
                }
                case 0x1D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x1E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x1F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x20:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x21:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x22:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x23:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x24:
                case 0xAE:
                case 0xE7:
                case 0xE8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x25:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x26:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x27:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x28:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x29:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    break;
                }
                case 0x2A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x2B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x2C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x2D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x2E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x2F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x30:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x31:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x32:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x33:
                case 0x5D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x34:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x35:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x36:
                case 0xBE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x37:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x38:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x39:
                case 0x5F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x3A:
                case 0x60:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x3B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x3C:
                case 0x62:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x3D:
                case 0x61:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x3E:
                case 0x96:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x3F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x40:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x41:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x42:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x43:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x44:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x45:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x46:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x47:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x48:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x49:
                case 0x50:
                case 0x73:
                case 0x80:
                case 0xEB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x4A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x4B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x4C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x4D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x4E:
                case 0x4F:
                case 0x52:
                case 0x71:
                case 0x72:
                case 0x79:
                case 0xA2:
                case 0xAD:
                case 0xB0:
                case 0xE3:
                case 0xEE:
                case 0xF2:
                case 0xF6:
                case 0xF7:
                case 0xF8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x51:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x53:
                case 0x9F:
                case 0xDD:
                case 0xF5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x55:
                case 0x57:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x56:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x58:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x59:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x5A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x5B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x5E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x63:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x64:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x65:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x66:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x67:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x68:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x69:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x6A:
                case 0x9A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x6B:
                case 0x74:
                case 0x81:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x6C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x6D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    ParseExpression(reader); // 11
                    break;
                }
                case 0x6E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x6F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x70:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x76:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x77:
                case 0x78:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x7A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x7E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x7F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x82:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x83:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x84:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x85:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x86:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x87:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x88:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x89:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x8A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x8B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x8C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x8D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x8E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x8F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x90:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x91:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x92:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x93:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x94:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x95:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x97:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x98:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x99:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x9B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x9C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x9D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x9E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xA0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0xA1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xA4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xA5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xA6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xA8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xA9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xAA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    break;
                }
                case 0xAB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xAC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xAF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xB2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xB3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xB4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    break;
                }
                case 0xB5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xB6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xB7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0xB8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0xB9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xBB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBD:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0xC0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xC1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xC2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xC3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xC8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    break;
                }
                case 0xCA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xCB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xCC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xCD:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xCE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    break;
                }
                case 0xCF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xD0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xD1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    ParseExpression(reader); // 11
                    break;
                }
                case 0xD2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xD3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    break;
                }
                case 0xD4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xD5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xD6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xD7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0xD8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xD9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xDE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xDF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xE0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xE1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xE2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xE4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xE5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xE9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xEA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xEC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xED:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    break;
                }
                case 0xEF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    break;
                }
                case 0xF0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    break;
                }
                case 0xF3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xF9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xFA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xFB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xFC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xFD:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xFE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xFF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                default:
                {
                    throw new Exception($"Unexpected function code {code:X2} at {addr:X8} .");
                }
            }
        }

        private void ParseFunctionV2(BinaryReader reader)
        {
            var addr = _codePos + Convert.ToInt32(reader.BaseStream.Position);
            var code = reader.ReadByte();

            switch (code)
            {
                case 0x00:
                {
                    Dis?.AppendLine($"{addr:X8} | push string");
                    Dis?.AppendLine($"{addr:X8} | ; type 0");
                    ParseStringReference(reader);
                    break;
                }
                case 0x01:
                {
                    Dis?.AppendLine($"{addr:X8} | push string");
                    Dis?.AppendLine($"{addr:X8} | ; type 1");
                    ParseStringReference(reader);
                    break;
                }
                case 0x02:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x03:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x04:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x05:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x06:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x07:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x08:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x09:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x0A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x0B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x0C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x0D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x0E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x0F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x10:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x11:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x12:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x13:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x14:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x15:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x16:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x17:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x18:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x19:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x1A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    break;
                }
                case 0x1B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    break;
                }
                case 0x1C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    ParseExpression(reader); // 11
                    break;
                }
                case 0x1D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x1E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x1F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x20:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x21:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x22:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x23:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x24:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x25:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x26:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x27:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x28:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x29:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    ParseExpression(reader); // 11
                    break;
                }
                case 0x2A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x2B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x2C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x2D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x2E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x2F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x30:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x31:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x32:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x33:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x34:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x35:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x36:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x37:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x38:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x39:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x3A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x3B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x3C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x3D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x3E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x3F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x40:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x41:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x42:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x43:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x44:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x45:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x46:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x47:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x48:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x49:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x4A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x4B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x4C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x4D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x4E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x4F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x50:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x51:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x52:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x53:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x54:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x55:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x56:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x57:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x58:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x59:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x5A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x5B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x5C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x5D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x5E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x5F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x60:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x61:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x62:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x63:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x64:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x65:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x66:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x67:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x68:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x69:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x6A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x6B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x6C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x6D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    ParseExpression(reader); // 11
                    break;
                }
                case 0x6E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x6F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x70:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x71:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x72:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x73:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x74:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x75:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x76:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x77:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x78:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x79:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x7A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x7B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x7C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x7D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x7E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x7F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x80:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x81:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x82:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x83:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x84:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x85:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x86:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x87:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x88:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x89:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x8A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x8B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x8C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x8D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x8E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x8F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x90:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x91:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x92:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x93:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0x94:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x95:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x96:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x97:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x98:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0x99:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0x9A:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x9B:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0x9C:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0x9D:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0x9E:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0x9F:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    reader.ReadUInt16();
                    break;
                }
                case 0xA0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xA1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xA2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xA3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xA4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xA5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xA6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xA7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xA8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xA9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    break;
                }
                case 0xAA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xAB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xAC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xAD:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xAE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xAF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xB0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xB1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xB2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xB3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    break;
                }
                case 0xB4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xB5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xB6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0xB7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0xB8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xB9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xBA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBD:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xBE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0xBF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xC0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xC1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xC2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xC7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xC8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    break;
                }
                case 0xC9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xCA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xCB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xCC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xCD:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    break;
                }
                case 0xCE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xCF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xD0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    ParseExpression(reader); // 11
                    break;
                }
                case 0xD1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xD2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    break;
                }
                case 0xD3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xD4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xD5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xD6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    break;
                }
                case 0xD7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xD8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xD9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xDA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xDB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xDC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0xDD:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    break;
                }
                case 0xDE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    break;
                }
                case 0xDF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    break;
                }
                case 0xE0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xE1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xE2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xE3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xE4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    break;
                }
                case 0xE5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xE6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xE7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    break;
                }
                case 0xE8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xE9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xEA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0xEB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xEC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    break;
                }
                case 0xED:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xEE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xEF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF0:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    ParseExpression(reader); // 4
                    ParseExpression(reader); // 5
                    ParseExpression(reader); // 6
                    ParseExpression(reader); // 7
                    ParseExpression(reader); // 8
                    ParseExpression(reader); // 9
                    ParseExpression(reader); // 10
                    break;
                }
                case 0xF1:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF2:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF3:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xF4:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    ParseExpression(reader); // 3
                    break;
                }
                case 0xF5:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF6:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF7:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF8:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xF9:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xFA:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xFB:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    break;
                }
                case 0xFC:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xFD:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseExpression(reader); // 1
                    ParseExpression(reader); // 2
                    break;
                }
                case 0xFE:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    break;
                }
                case 0xFF:
                {
                    Dis?.AppendLine($"{addr:X8} | func_{code:X2}");
                    ParseStringReference(reader); // s1
                    break;
                }
                default:
                {
                    throw new Exception($"Unexpected function code {code:X2} at {addr:X8} .");
                }
            }
        }

        private void ParseExpression(BinaryReader reader)
        {
            int addr;
            int code;
            int flag;

            // addr = _codePos + Convert.ToInt32(reader.BaseStream.Position);

            // Dis?.AppendLine($"{addr:X8} | ; Start of expression");

            while (true)
            {
                // Load data to expression stack

                while (true)
                {
                    // addr = _codePos + Convert.ToInt32(reader.BaseStream.Position);
                    flag = reader.ReadByte();

                    if (flag != 0)
                    {
                        break;
                    }

                    addr = _codePos + Convert.ToInt32(reader.BaseStream.Position);

                    var reg = reader.ReadByte();
                    var mask = reader.ReadUInt16();

                    Dis?.AppendLine($"{addr:X8} | load 0x{reg:X2} 0x{mask:X4}");
                }

                if (flag == 0xFF)
                {
                    // Dis?.AppendLine($"{addr:X8} | ; End of expression");
                    return;
                }

                // Execute Operator (optional)

                addr = _codePos + Convert.ToInt32(reader.BaseStream.Position);
                code = reader.ReadByte();

                switch (code)
                {
                    case 0x00:
                    {
                        Dis?.AppendLine($"{addr:X8} | greater");
                        break;
                    }
                    case 0x01:
                    {
                        Dis?.AppendLine($"{addr:X8} | less_equal");
                        break;
                    }
                    case 0x02:
                    {
                        Dis?.AppendLine($"{addr:X8} | not_equal");
                        break;
                    }
                    case 0x03:
                    {
                        Dis?.AppendLine($"{addr:X8} | equal");
                        break;
                    }
                    case 0x04:
                    {
                        Dis?.AppendLine($"{addr:X8} | greater_equal");
                        break;
                    }
                    case 0x05:
                    {
                        Dis?.AppendLine($"{addr:X8} | less");
                        break;
                    }
                    case 0x0A:
                    {
                        Dis?.AppendLine($"{addr:X8} | is_zero");
                        break;
                    }
                    case 0x0B:
                    {
                        Dis?.AppendLine($"{addr:X8} | logical_and");
                        break;
                    }
                    case 0x0C:
                    {
                        Dis?.AppendLine($"{addr:X8} | logical_or");
                        break;
                    }
                    case 0x14:
                    {
                        Dis?.AppendLine($"{addr:X8} | add");
                        break;
                    }
                    case 0x15:
                    {
                        Dis?.AppendLine($"{addr:X8} | sub");
                        break;
                    }
                    case 0x16:
                    {
                        Dis?.AppendLine($"{addr:X8} | mul");
                        break;
                    }
                    case 0x17:
                    {
                        Dis?.AppendLine($"{addr:X8} | div");
                        break;
                    }
                    case 0x18:
                    {
                        Dis?.AppendLine($"{addr:X8} | mod");
                        break;
                    }
                    default:
                    {
                        throw new Exception($"Unexpected operator {code:X2} at {addr:X8} .");
                    }
                }
            }

            // _Dis?.AppendLine($"{addr:X8} | ; End of expression");
        }

        private void ParseStringReference(BinaryReader reader)
        {
            var addr = _codePos + Convert.ToInt32(reader.BaseStream.Position);

            var refAddr = Convert.ToInt32(reader.BaseStream.Position);
            var offset = reader.ReadUInt16();

            if (offset >= _stringPool.Length)
            {
                throw new Exception("Unexpected string offset.");
            }

            _stringRef.Add(refAddr);

            var bytes = _stringPool.Skip(offset)
                .TakeWhile(x => x != 0)
                .ToArray();

            var s = _encoding.GetString(bytes);

            Dis?.AppendLine($"{addr:X8} | ; ref \"{s}\" ");
        }

        public void ExportDisasm(string filePath)
        {
            File.WriteAllText(filePath, _disassembly);
        }

        public void ExportText(string filePath)
        {
            using var writer = File.CreateText(filePath);

            var codeReader = new BinaryReader(new MemoryStream(_codeBuffer));

            foreach (var addr in _stringRef)
            {
                codeReader.BaseStream.Position = addr;

                int offset = codeReader.ReadUInt16();

                var text = _stringPool.ReadNullTerminatedString(offset, _encoding)
                    .Escape();

                if (string.IsNullOrWhiteSpace(text))
                {
                    continue;
                }

                writer.WriteLine("◇{0:X8}◇{1}", addr, text);
                writer.WriteLine("◆{0:X8}◆{1}", addr, text);
                writer.WriteLine();
            }

            writer.Flush();
            writer.Close();
        }

        public void ImportText(string filePath, Encoding encoding)
        {
            var translation = Translation.Load(filePath);

            var codeWriter = new BinaryWriter(new MemoryStream(_codeBuffer));

            var stringPoolStream = new MemoryStream();
            var stringWriter = new BinaryWriter(stringPoolStream);

            // Keep the original strings and add new strings.
            // This increases the file size but can reduce data errors caused by incomplete code analysis.
            stringWriter.Write(_stringPool);

            // NOTE: This method may bring another problem. When the strings is too long,
            // it may cause offset overflow because the maximum value of offset is ushort.MaxValue.

            // Compact strings
            var cache = new Dictionary<string, int>();

            foreach (var addr in _stringRef)
            {
                if (translation.TryGetValue(addr, out var text))
                {
                    // Read original string
                    var originalOffset = BitConverter.ToUInt16(_codeBuffer, addr);
                    var originalString = _stringPool.ReadNullTerminatedString(originalOffset, _encoding);

                    // We ignore strings that have not changed
                    if (text == originalString)
                    {
                        continue;
                    }

                    if (!cache.TryGetValue(text, out var offset))
                    {
                        offset = Convert.ToUInt16(stringWriter.BaseStream.Position);
                        cache.Add(text, offset);
                    }

                    // Add new string to pool
                    stringWriter.WriteNullTerminatedString(text, encoding);
                    stringWriter.Write((byte)0);

                    // Update reference
                    codeWriter.BaseStream.Position = addr;
                    codeWriter.Write(Convert.ToUInt16(offset));
                }
            }

            _stringPool = stringPoolStream.ToArray();
        }

        public void ImportTextRebuild(string filePath, Encoding encoding)
        {
            var translation = Translation.Load(filePath);

            var codeWriter = new BinaryWriter(new MemoryStream(_codeBuffer));

            var stringPoolStream = new MemoryStream();
            var stringWriter = new BinaryWriter(stringPoolStream);

            // Compact strings
            var cache = new Dictionary<string, int>();

            foreach (var addr in _stringRef)
            {
                // Read original string
                var originalOffset = BitConverter.ToUInt16(_codeBuffer, addr);
                var originalString = _stringPool.ReadNullTerminatedString(originalOffset, _encoding);

                // Match translation
                if (!translation.TryGetValue(addr, out var newString))
                {
                    newString = originalString;
                }

                if (!cache.TryGetValue(newString, out var offset))
                {
                    // Get new offset
                    offset = Convert.ToUInt16(stringWriter.BaseStream.Position);

                    cache.Add(newString, offset);

                    // Add new string to pool
                    stringWriter.WriteNullTerminatedString(newString, encoding);
                    stringWriter.Write((byte)0);
                }

                // Update reference
                codeWriter.BaseStream.Position = addr;
                codeWriter.Write(Convert.ToUInt16(offset));
            }

            _stringPool = stringPoolStream.ToArray();
        }
    }
}
