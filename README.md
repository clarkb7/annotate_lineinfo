# annotate_lineinfo

This IDAPython script/plugin will parse the PDB for the loaded executable and annotate the disassembly with source and line number information.

## Usage

### Script
* Option 1) Run [annotate_lineinfo.py](annotate_lineinfo/annotate_lineinfo.py) as a regular IDAPython script.

* Option 2) From another script or the IDAPython console:
```python
import annotate_lineinfo
annotate_lineinfo.ida_annotate_lineinfo()
```

### Plugin
To install
* Place [annotate_lineinfo_plugin.py](annotate_lineinfo_plugin.py) in the `plugins` directory of your IDA installation.

Annotate entire file
* Use shortcut key `Alt-A` or run from plugins menu.

Disassembly view popup menu
* Right click inside a function, select annotate
* Select a range of instructions, right click, select annotate

Functions view popup menu
* Select one or more functions, right click, select annotate

## Caveats
Only runs on Windows. This script makes use of the COM API provided by msdia[ver].dll to parse the PDB.
