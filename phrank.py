import idaapi

idaapi.require("phrank.phrank_settings")
idaapi.require("phrank.phrank_util")
idaapi.require("phrank.phrank_func")

idaapi.require("phrank.phrank_hexrays")

idaapi.require("phrank.phrank_struct_analysis")
idaapi.require("phrank.phrank_containers")
idaapi.require("phrank.phrank_cpp")

idaapi.require("phrank_api")

import phrank_api
import phrank.phrank_hexrays as p_hrays


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

		rv = self.handler(cfunc, citem)
		if rv == 1:
			hx_view.refresh_view(1)
		return rv

	def handler(self, cfunc, citem):
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
	def __init__(self, action_name, hotkey, label):
		super().__init__(action_name, hotkey, label)

	def handler(self, cfunc, citem):
		if citem.citype != idaapi.VDI_EXPR:
			return 0

		expr = citem.it.to_specific_type
		intval = p_hrays.get_int(expr)
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
	def __init__(self, action_name, hotkey, label):
		super().__init__(action_name, hotkey, label)

	def handler(self, cfunc, citem):
		if citem.citype != idaapi.VDI_EXPR:
			return 0

		expr = citem.it.to_specific_type
		if expr.op != idaapi.cot_var:
			print("no variable found under cursor")
			return 0

		phrank_api.analyze_variable(cfunc, expr.v.idx)
		return 1

actions = [
	# will create vtable structure from the address calculated from int cexpr value
	VtableMaker("phrank::vtable_maker", "Alt-Q", "make vtable"),

	# will calculate size of the pointer in variable at cursor
	# then will create struct structure with that size or adjust size of existing one
	# then will set variable to new type, if created
	StructMaker("phrank::struct_maker", "Shift-A", "make struct"),
]

def register_actions(*actions):
	for a in actions:
		a.register()

register_actions(*actions)