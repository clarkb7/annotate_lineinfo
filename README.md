# annotate_lineinfo

This IDAPython script will parse the PDB for the loaded executable and annotate the disassembly with source and line number information.

## Usage

Run as a regular IDAPython script

From another script or the IDAPython console
```python
import annotate_lineinfo
ida_annotate_lineinfo(idaapi.get_input_file_path())
```

## Caveats
Only runs on Windows. This script makes use of the COM API provided by msdia[ver].dll to parse the PDB.
