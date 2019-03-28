"""
IDA plugin for annotate_lineinfo

Copyright (c) 2019 Branden Clark [github.com/clarkb7]
MIT License, see LICENSE for details.
"""
import idaapi
import annotate_lineinfo.annotate_lineinfo as ali

PLUGIN_COMMENT = "Annotate IDA with source and line number information from a PDB"
PLUGIN_HELP = "github.com/clarkb7/annotate_lineinfo"
PLUGIN_NAME = "annotate_lineinfo"
PLUGIN_WANTED_HOTKEY = 'Alt-A'

ali_plugin = None

class ALI_DISASM_SelectionHandler(idaapi.action_handler_t):
    """Annotate selection with line info"""
    def activate(self, ctx):
        selelection,start,end = idaapi.read_selection()
        length = end-start
        ali.ida_add_lineinfo_comment_to_range(ali_plugin.dia, start, length)

class ALI_DISASM_FunctionHandler(idaapi.action_handler_t):
    """Annotate function with line info"""
    def activate(self, ctx):
        ida_func = idaapi.get_func(ScreenEA())
        length = ida_func.size()+1
        ali.ida_add_lineinfo_comment_to_range(ali_plugin.dia, ida_func.startEA, length)

class ALI_Hooks(idaapi.UI_Hooks):
    def finish_populating_tform_popup(self, form, popup):
	tft = idaapi.get_tform_type(form)
	if tft == idaapi.BWN_DISASM: # Disassembly view
            desc = None
            # Choose either selection or function annotation depending on cursor
            selection = idaapi.read_selection()
            if selection[0] == True:
                desc = idaapi.action_desc_t(None,
                    'Annotate selection with line info', ALI_DISASM_SelectionHandler())
            else:
                func = idaapi.get_func(ScreenEA())
                if func is not None:
                    desc = idaapi.action_desc_t(None,
                        'Annotate function with line info', ALI_DISASM_FunctionHandler())
            # Add corresponding action to popup menu
            if desc is not None:
	        idaapi.attach_dynamic_action_to_popup(form, popup, desc, None)

class ALI_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_WANTED_HOTKEY

    def init(self):
        idaapi.autoWait()
        idaapi.msg("[annotate_lineinfo] loaded!\n")
        self.dia = ali.DIASession(idaapi.get_input_file_path())
        self.hooks = ALI_Hooks()
        self.hooks.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        ali.ida_annotate_lineinfo()

    def term(self):
        idaapi.msg("[annotate_lineinfo] unloading!\n")

def PLUGIN_ENTRY():
    global ali_plugin
    ali_plugin = ALI_plugin_t()
    return ali_plugin

