"""
IDA plugin for annotate_lineinfo

Copyright (c) 2019 Branden Clark [github.com/clarkb7]
MIT License, see LICENSE for details.
"""
import idaapi
import annotate_lineinfo

PLUGIN_COMMENT = "Annotate IDA with source and line number information from a PDB"
PLUGIN_HELP = "github.com/clarkb7/annotate_lineinfo"
PLUGIN_NAME = "annotate_lineinfo"
PLUGIN_WANTED_HOTKEY = 'Alt-A'

class annotate_lineinfo_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_WANTED_HOTKEY

    def init(self):
        idaapi.msg("[annotate_lineinfo] loaded!\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        annotate_lineinfo.ida_annotate_lineinfo()

    def term(self):
        idaapi.msg("[annotate_lineinfo] unloading!\n")

def PLUGIN_ENTRY():
    return annotate_lineinfo_plugin_t()

