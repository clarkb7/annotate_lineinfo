# annotate_lineinfo

This IDAPython script will parse the PDB for the loaded executable and annotate the disassembly with source and line number information.

## Usage

Options
* Run [annotate_lineinfo.py](annotate_lineinfo/annotate_lineinfo.py) as a regular IDAPython script.

* Place [annotate_lineinfo_plugin.py](annotate_lineinfo_plugin.py) in the `plugins` directory of your IDA installation.
  * Use shortcut key `Alt-A` or run from plugins menu.

* From another script or the IDAPython console:
```python
import annotate_lineinfo
annotate_lineinfo.ida_annotate_lineinfo()
```

## Caveats
Only runs on Windows. This script makes use of the COM API provided by msdia[ver].dll to parse the PDB.
