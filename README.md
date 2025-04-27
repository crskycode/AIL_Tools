# AILSystem Tools

This toolkit is designed for modifying games developed with the AILSystem engine.

## Resource Packs

Resource pack files for this engine have the `.DAT` or `.SNL` extension.

### Extracting Files from a Resource Pack

Run the following command:
```
ArcTool -e -in input.DAT -out Extract
```

Parameter Description:
- `-e`: Extract files from the resource pack.
- `-in`: Specify the resource pack filename.
- `-out`: Specify the directory where extracted items will be stored.

### Creating a Resource Pack

Run the following command:
```
ArcTool -c -in RootDirectory -out res.DAT
```

Parameter Description:
- `-c`: Create a resource pack.
- `-in`: Specify the folder containing files you wish to add to the resource pack.
- `-out`: Specify the resource pack filename.

## Scripts

Script files for this engine is no extension and do not have an identifier in the file header.

### Disassembling Scripts

Run the following command:
```
ScriptTool -d -in input.bin -icp shift_jis -out output.txt
```

Parameter Description:
- `-d`: Disassemble analysis.
- `-in`: Specify the script filename.
- `-icp`: Specify the encoding of text within the script file. This is usually `shift_jis`.
- `-out`: Specify the output filename.

### Extracting Text from Scripts

Run the following command:
```
ScriptTool -e -in input.bin -icp shift_jis -out output.txt
```

Parameter Description:
- `-e`: Extract text.
- `-in`: Specify the script filename.
- `-icp`: Specify the encoding of text within the script file. This is usually `shift_jis`.
- `-out`: Specify the output filename.

### Importing Text into Scripts

Run the following command:
```
ScriptTool -i -in input.bin -icp shift_jis -out output.bin -ocp shift_jis -txt input.txt
```

Parameter Description:
- `-i`: Import text.
- `-in`: Specify the script filename.
- `-icp`: Specify the encoding of text within the script file. This is usually `shift_jis`.
- `-out`: Specify the output filename.
- `-ocp`: Specify the encoding of text within the output script file. This is usually `shift_jis`.
- `-txt`: Specify the filename of the file containing text you wish to import.

In addition, you can also use the following command to import text.

Run the following command:
```
ScriptTool -b -in input.bin -icp shift_jis -out output.bin -ocp shift_jis -txt input.txt
```

**Warning:** This method will rebuild the full string section, which can reduce the possibility of string offset overflow, but may cause data errors.

---

**Note:** This toolkit has been tested on a limited number of games only.
