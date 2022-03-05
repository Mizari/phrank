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


class VtableMaker(idaapi.action_handler_t):
	def __init__(self):
		super().__init__()

	def activate(self, ctx):
		if ctx.widget_type != idaapi.BWN_PSEUDOCODE:
			return 0

		hx_view = idaapi.get_widget_vdui(ctx.widget)
		cfunc = hx_view.cfunc
		citem = hx_view.item
		intval = phrank_api.citem_to_int(cfunc, citem)
		if intval == idaapi.BADADDR:
			print("Failed to get int value")
			return 0

		vtbl = phrank_api.create_vtable(intval)
		if vtbl is None:
			print("failed to create vtable at", hex(intval))
		else:
			print("successfully created vtable", vtbl.get_name(), "at", hex(intval))
		return 1

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

class StructMaker(idaapi.action_handler_t):
	def __init__(self):
		super().__init__()

	def activate(self, ctx):
		if ctx.widget_type != idaapi.BWN_PSEUDOCODE:
			return 0

		hx_view = idaapi.get_widget_vdui(ctx.widget)
		cfunc = hx_view.cfunc
		citem = hx_view.item
		if citem.citype != idaapi.VDI_EXPR:
			return 0
		
		expr = citem.it

		while expr is not None:
			expr = expr.to_specific_type
			if expr.op == idaapi.cot_var:
				break
			expr = cfunc.body.find_parent_of(expr)

		if expr is None:
			print("no variable found under cursor")
			return 0

		phrank_api.analyze_variable(cfunc, expr.v.idx)
		hx_view.refresh_view(1)

		return 1

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

vtable_handler = VtableMaker()
struct_handler = StructMaker()

def register_actions():
	action_name = "phrank::vtable_maker"
	current_state = idaapi.get_action_state(action_name)
	if current_state[0]:
		idaapi.unregister_action(action_name)
	idaapi.register_action(
		idaapi.action_desc_t(action_name, "make vtable", vtable_handler, "Alt-Q")
	)
	idaapi.update_action_state(action_name, idaapi.AST_ENABLE_ALWAYS)

	action_name = "phrank::struct_maker"
	current_state = idaapi.get_action_state(action_name)
	if current_state[0]:
		idaapi.unregister_action(action_name)
	idaapi.register_action(
		idaapi.action_desc_t(action_name, "make struct", struct_handler, "Shift-A")
	)
	idaapi.update_action_state(action_name, idaapi.AST_ENABLE_ALWAYS)


register_actions()