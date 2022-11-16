import idaapi

import phrank_api
import phrank.util_ast as p_hrays


def get_lvar_id(cfunc, lvar_arg):
	for lvar_id, lvar in enumerate(cfunc.lvars):
		if lvar_arg.name == lvar.name:
			return lvar_id
	return -1


class HRActionHandler(idaapi.action_handler_t):
	def __init__(self, action_name, hotkey, label):
		idaapi.action_handler_t.__init__(self)
		self.action_name = action_name
		self.hotkey = hotkey
		self.label = label
	
	def can_activate(self, ctx):
		if ctx.widget_type != idaapi.BWN_PSEUDOCODE:
			return False
		return True

	def activate(self, ctx):
		if not self.can_activate(ctx):
			return 0

		hx_view = idaapi.get_widget_vdui(ctx.widget)
		cfunc = hx_view.cfunc
		citem = hx_view.item

		should_refresh = 0
		if citem.citype == idaapi.VDI_EXPR:
			citem = citem.it.to_specific_type
			should_refresh = self.handle_expr(cfunc, citem)
		elif citem.citype == idaapi.VDI_LVAR:
			lvar_id = get_lvar_id(cfunc, citem.l)
			should_refresh = self.handle_lvar(cfunc, lvar_id)
		elif citem.citype == idaapi.VDI_FUNC:
			should_refresh = self.handle_function(cfunc)

		if should_refresh == 1:
			hx_view.refresh_view(1)
		return should_refresh

	def handle_expr(self, cfunc, citem):
		raise NotImplementedError()

	def handle_lvar(self, cfunc, lvar_id):
		raise NotImplementedError()

	def handle_function(self, cfunc):
		raise NotImplementedError()

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

	def register(self):
		current_state = idaapi.get_action_state(self.action_name)
		if current_state[0]:
			idaapi.unregister_action(self.action_name)
		idaapi.register_action(
			idaapi.action_desc_t(self.action_name, "qwe", self, self.hotkey)
		)
		idaapi.update_action_state(self.action_name, idaapi.AST_ENABLE_ALWAYS)


class VtableMaker(HRActionHandler):
	def handl_expr(self, cfunc, citem):
		intval = p_hrays.get_int(citem)
		if intval is None:
			print("Failed to get int value")
			return 0

		vtbl = phrank_api.create_vtable(intval)
		if vtbl is None:
			print("failed to create vtable at", hex(intval))
			return 0
		else:
			print("successfully created vtable", vtbl.get_name(), "at", hex(intval))
			return 1


class StructMaker(HRActionHandler):
	def handle_function(self, cfunc):
		phrank_api.analyze_function(cfunc)
		return 1

	def handle_lvar(self, cfunc, lvar_id):
		struct_analyzer = phrank_api.StructAnalyzer()
		struct_analyzer.analyze_lvar(cfunc.entry_ea, lvar_id)
		struct_analyzer.apply_analysis()
		return 1

	def handle_expr(self, cfunc, citem):
		if citem.op == idaapi.cot_cast:
			citem = citem.x

		if citem.op == idaapi.cot_obj:
			struct_analyzer = phrank_api.StructAnalyzer()
			struct_analyzer.analyze_gvar(citem.obj_ea)
			struct_analyzer.apply_analysis()
			return 1

		if citem.op == idaapi.cot_var:
			return self.handle_lvar(cfunc, citem.v.idx)

		print("unknown citem under cursor", citem.opname)
		return 0


# will create vtable structure from the address calculated from int cexpr value
VtableMaker("phrank::vtable_maker", "Alt-Q", "make vtable").register()

# will calculate size of the pointer in variable at cursor
# then will create struct structure with that size or adjust size of existing one
# then will set variable to new type, if created
StructMaker("phrank::struct_maker", "Shift-A", "make struct").register()


class PhrankPlugin(idaapi.plugin_t):
	flags = 0
	wanted_name = "phrank"
	comment = ""
	help = ""
	wanted_hotkey = ""

	def init(self):
		return idaapi.PLUGIN_SKIP
	
	def run(self, arg):
		return

	def term(self):
		return

def PLUGIN_ENTRY():
	return PhrankPlugin()