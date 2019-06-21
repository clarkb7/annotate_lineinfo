# annotate_lineinfo

This IDAPython script/plugin will parse the PDB for the loaded executable and annotate the disassembly with source and line number information.

<p align="center">
<img alt="WinDbg TTD tutorial sample screenshot" src="https://raw.github.com/clarkb7/annotate_lineinfo/master/screenshots/main.png?sanitize=true"/>
</p>

## Usage

### Script
* Option 1) Run [annotate_lineinfo.py](https://github.com/clarkb7/annotate_lineinfo/blob/master/annotate_lineinfo/annotate_lineinfo.py) as a regular IDAPython script.

* Option 2) From another script or the IDAPython console:
```python
import annotate_lineinfo
annotate_lineinfo.ida_annotate_lineinfo()
```

### Plugin
To install
* Option 1) Run `python setup.py install --install-ida-plugin=PATH` to install [annotate_lineinfo_plugin.py](https://github.com/clarkb7/annotate_lineinfo/blob/master/annotate_lineinfo_plugin.py) to `PATH\plugins`
  * If `PATH` is not specified, `%IDAUSR%` will be tried first
  * If `%IDAUSR%` does not exist, it defaults to `%APPDATA%\Hex-Rays\IDA Pro`
* Option 2) Manually place [annotate_lineinfo_plugin.py](https://github.com/clarkb7/annotate_lineinfo/blob/master/annotate_lineinfo_plugin.py) in the `plugins` directory of your IDA installation.

Annotate entire file
* Use shortcut key `Alt-Shift-A` or run from `Edit->Annotate lineinfo` menu.

Disassembly view popup menu
* Right click inside a function, select annotate
* Select a range of instructions, right click, select annotate

Functions view popup menu
* Select one or more functions, right click, select annotate

Each of the above actions has a corresponding `remove annotations` action.

On load, annotate_lineinfo attempts to locate the PDB in the following locations:
* `_NT_SYMBOL_PATH` if set
* IDA's default PDB download directory `%TEMP%\ida`
* MSDIA defaults - Path in debug directory of executable, same path as executable

You may specify the PDB path manually, or request another auto-locate attempt (e.g. after IDA downloads the PDB),
from the `Edit->Annotate lineinfo` menu.

## Caveats
Only runs on Windows. This script makes use of the COM API provided by msdia[ver].dll to parse the PDB.
