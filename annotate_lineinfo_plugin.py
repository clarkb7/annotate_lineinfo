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
PLUGIN_WANTED_HOTKEY = 'Alt-Shift-A'

def ALI_MSG(msg,EOL="\n"):
    idaapi.msg("[{}] {}{}".format(PLUGIN_NAME, msg, EOL))

ACTION_ADD_ANNOTATION = 0
ACTION_DEL_ANNOTATION = 1

ali_plugin = None
try:
    idaapi.action_handler_t
except AttributeError:
    ALI_MSG("IDA action API unavailable")
    ALI_IDA_ACTION_API = False
else:
    ALI_IDA_ACTION_API = True
    class ALI_DISASM_SelectionHandler(idaapi.action_handler_t):
        """Dynamic action handler. Annotate selection with line info"""
        def __init__(self, action):
            idaapi.action_handler_t.__init__(self)
            self._action = action

        def activate(self, ctx):
            try:
                # from is a reserved keyword in python...
                cur_sel_from = getattr(ctx.cur_sel, "from")
                start,end = (x.at.toea() for x in [cur_sel_from, ctx.cur_sel.to])
            except AttributeError:
                _,start,end = idaapi.read_selection()
            length = end-start
            if self._action == ACTION_ADD_ANNOTATION:
                ali.ida_add_lineinfo_comment_to_range(ali_plugin.dia, start, length)
            elif self._action == ACTION_DEL_ANNOTATION:
                ali.ida_del_lineinfo_comment_from_range(start, length)

    class ALI_DISASM_FunctionHandler(idaapi.action_handler_t):
        """Dynamic action handler. Annotate function with line info"""
        def __init__(self, action):
            idaapi.action_handler_t.__init__(self)
            self._action = action
        def activate(self, ctx):
            ida_func = ctx.cur_func
            if self._action == ACTION_ADD_ANNOTATION:
                ali.ida_add_lineinfo_comment_to_func(ali_plugin.dia, ida_func)
            elif self._action == ACTION_DEL_ANNOTATION:
                ali.ida_del_lineinfo_comment_from_func(ida_func)

    class ALI_FUNCS_Handler(idaapi.action_handler_t):
        """Action handler. Annotate function with line info"""
        def __init__(self, action):
            idaapi.action_handler_t.__init__(self)
            self._action = action
        def activate(self, ctx):
            for pfn_id in ctx.chooser_selection:
                ida_func = idaapi.getn_func(pfn_id-1)
                if self._action == ACTION_ADD_ANNOTATION:
                    ali.ida_add_lineinfo_comment_to_func(ali_plugin.dia, ida_func)
                elif self._action == ACTION_DEL_ANNOTATION:
                    ali.ida_del_lineinfo_comment_from_func(ida_func)
            return 1
        def update(self, ctx):
            return idaapi.AST_ENABLE_FOR_FORM

    class ALI_MENU_AnnotateHandler(idaapi.action_handler_t):
        """Menu action handler. Annotate entire file with line info"""
        def __init__(self, action):
            idaapi.action_handler_t.__init__(self)
            self._action = action
        def activate(self, ctx):
            if self._action == ACTION_ADD_ANNOTATION:
                ali.ida_annotate_lineinfo_dia(ali_plugin.dia)
            elif self._action == ACTION_DEL_ANNOTATION:
                ali.ida_del_annotations()
            return 1
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class ALI_MENU_ChoosePDBHandler(idaapi.action_handler_t):
        """Menu action handler. Choose PDB file to load info from"""
        def activate(self, ctx):
            args = [False, "*.pdb", "Enter path to PDB file"]
            try:
                pdbpath = idaapi.ask_file(*args)
            except AttributeError:
                pdbpath = idc.AskFile(*args)
            if pdbpath is None:
                return 0
            if not ali_plugin.init_dia(inbin_path=pdbpath):
                return 0
            if not ali_plugin.attach_actions():
                return 0
            return 1
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class ALI_MENU_RetryPDBHandler(idaapi.action_handler_t):
        """Menu action handler. Retry auto-find PDB file"""
        def activate(self, ctx):
            if not ali_plugin.init_dia():
                return 0
            if not ali_plugin.attach_actions():
                return 0
            return 1
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class ALI_Hooks(idaapi.UI_Hooks):
        def finish_populating_tform_popup(self, form, popup):
            tft = idaapi.get_tform_type(form)
            if tft == idaapi.BWN_DISASM: # Disassembly view
                descs = []
                # Choose either selection or function annotation depending on cursor
                selection = idaapi.read_selection()
                if selection[0] == True:
                    descs.append(idaapi.action_desc_t(None,
                        'Annotate selection with line info',
                        ALI_DISASM_SelectionHandler(ACTION_ADD_ANNOTATION)))
                    descs.append(idaapi.action_desc_t(None,
                        'Remove annotations from selection',
                        ALI_DISASM_SelectionHandler(ACTION_DEL_ANNOTATION)))
                else:
                    func = idaapi.get_func(ScreenEA())
                    if func is not None:
                        descs.append(idaapi.action_desc_t(None,
                            'Annotate function with line info',
                            ALI_DISASM_FunctionHandler(ACTION_ADD_ANNOTATION)))
                        descs.append(idaapi.action_desc_t(None,
                            'Remove annotations from function',
                            ALI_DISASM_FunctionHandler(ACTION_DEL_ANNOTATION)))
                # Add corresponding action to popup menu
                for d in descs:
                    idaapi.attach_dynamic_action_to_popup(form, popup, d, None)
            elif tft == idaapi.BWN_FUNCS: # Functions view
                # Add action to popup menu
                idaapi.attach_action_to_popup(form, popup,
                    type(ali_plugin).action_wfuncs_add_name, None,
                    idaapi.SETMENU_INS)
                idaapi.attach_action_to_popup(form, popup,
                    type(ali_plugin).action_wfuncs_del_name, None,
                    idaapi.SETMENU_INS)

class ALI_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ''

    menu_path = "Edit/Annotate lineinfo/"
    action_wfuncs_add_name = 'ali:wfuncs_add'
    action_wfuncs_add_label = "Annotate function(s) with line info"
    action_wfuncs_del_name = 'ali:wfuncs_del'
    action_wfuncs_del_label = "Remove annotations from function(s)"
    action_menu_annotate_name = 'ali:menu_annotate'
    action_menu_annotate_label = "Annotate entire input file"
    action_menu_delannotate_name = 'ali:menu_delannotate'
    action_menu_delannotate_label = "Remove all annotations"
    action_menu_loadpdb_name = 'ali:menu_loadpdb'
    action_menu_loadpdb_label = "Choose PDB file..."
    action_menu_retrypdb_name = 'ali:menu_retrypdb'
    action_menu_retrypdb_label = "Retry auto-find PDB"

    def init(self):
        self.dia = None
        self.hooks = None

        idaapi.autoWait()

        if not self.init_dia():
            ALI_MSG("Please specify PDB file path using '{}{}'".format(
                    type(self).menu_path,type(self).action_menu_loadpdb_label))

        if ALI_IDA_ACTION_API:
            # Register actions
            actions = [
                idaapi.action_desc_t(
                    type(self).action_wfuncs_add_name, type(self).action_wfuncs_add_label,
                    ALI_FUNCS_Handler(ACTION_ADD_ANNOTATION)),
                idaapi.action_desc_t(
                    type(self).action_wfuncs_del_name, type(self).action_wfuncs_del_label,
                    ALI_FUNCS_Handler(ACTION_DEL_ANNOTATION)),
                idaapi.action_desc_t(
                    type(self).action_menu_annotate_name, type(self).action_menu_annotate_label,
                    ALI_MENU_AnnotateHandler(ACTION_ADD_ANNOTATION), PLUGIN_WANTED_HOTKEY),
                idaapi.action_desc_t(
                    type(self).action_menu_delannotate_name, type(self).action_menu_delannotate_label,
                    ALI_MENU_AnnotateHandler(ACTION_DEL_ANNOTATION)),
                idaapi.action_desc_t(
                    type(self).action_menu_loadpdb_name, type(self).action_menu_loadpdb_label,
                    ALI_MENU_ChoosePDBHandler()),
                idaapi.action_desc_t(
                    type(self).action_menu_retrypdb_name, type(self).action_menu_retrypdb_label,
                    ALI_MENU_RetryPDBHandler()),
            ]
            for action in actions:
                if not idaapi.register_action(action):
                    ALI_MSG("Failed to register action: {}".format(action.name))
                    return idaapi.PLUGIN_SKIP

            # Attach actions
            if not self.attach_actions():
                return idaapi.PLUGIN_SKIP

        ALI_MSG("loaded!")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        ALI_MSG("unloading!")
        if ALI_IDA_ACTION_API:
            if self.hooks is not None:
                self.hooks.unhook()
            idaapi.unregister_action(type(self).action_wfuncs_add_name)
            idaapi.unregister_action(type(self).action_wfuncs_del_name)
            idaapi.unregister_action(type(self).action_menu_annotate_name)
            idaapi.unregister_action(type(self).action_menu_loadpdb_name)
            idaapi.unregister_action(type(self).action_menu_retrypdb_name)

    def init_dia(self, inbin_path=None, sympaths=None):
        if inbin_path is None:
            inbin_path = idaapi.get_input_file_path()
            if inbin_path is None:
                ALI_MSG("No file loaded")
                return False

        if sympaths is None:
            sympaths = []
            ida_sympath = ali.ida_get_sympath()
            if ida_sympath is not None:
                sympaths.append(ida_sympath)

        try:
            self.dia = ali.DIASession(inbin_path, sympaths=sympaths)
        except ValueError as e:
            ALI_MSG("Error loading PDB: {}".format(e))
            return False
        ALI_MSG("Loaded PDB info!")
        return True

    def attach_actions(self):
        if ALI_IDA_ACTION_API:
            # Menu actions
            menu_actions = [
                type(self).action_menu_loadpdb_name,
                type(self).action_menu_retrypdb_name,
            ]
            if self.ready():
                menu_actions += [
                    type(self).action_menu_annotate_name,
                    type(self).action_menu_delannotate_name,
                ]
            for name in menu_actions:
                if not idaapi.attach_action_to_menu(
                    type(self).menu_path,
                    name, idaapi.SETMENU_APP):
                    ALI_MSG("Failed to attach action: {}".format(name))
                    return False

            # UI Hooks
            if self.ready() and self.hooks is None:
                self.hooks = ALI_Hooks()
                if not self.hooks.hook():
                    ALI_MSG("Failed to install UI hooks")
                    return False
        return True

    def ready(self):
        return self.dia is not None

def PLUGIN_ENTRY():
    global ali_plugin
    ali_plugin = ALI_plugin_t()
    return ali_plugin

