import idaapi

idaapi.require("phrank.phrank_func")
idaapi.require("phrank.phrank_cpp")
idaapi.require("phrank.phrank_containers")
idaapi.require("phrank.phrank_hexrays")
idaapi.require("phrank.phrank_util")
idaapi.require("phrank.phrank_settings")
idaapi.require("phrank_api")

import phrank_api


class VtableMaker(idaapi.action_handler_t):
	def __init__(self):
		super().__init__()

	def activate(self, ctx):
		if ctx.widget_type != idaapi.BWN_PSEUDOCODE:
			return

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


def register_actions():
	idaapi.unregister_action("vtblmkr")

	idaapi.register_action(
		idaapi.action_desc_t("vtblmkr", "make vtable", VtableMaker(), "Alt-Q")
	)


register_actions()