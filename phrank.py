import idaapi
idaapi.require("phrank_func")
idaapi.require("phrank_cpp")
idaapi.require("phrank_containers")
idaapi.require("phrank_hexrays")
idaapi.require("phrank_util")

import phrank_cpp
import phrank_containers
import phrank_hexrays

def analyze_everything():
	phrank_cpp.CppClassFactory().analyze_everything()

def analyze_func(addr):
	phrank_cpp.CppClassFactory().analyze_func(addr)

def analyze_vtable(addr):
	phrank_cpp.CppClassFactory().analyze_vtable(addr)

def create_cpp_vtables():
	phrank_cpp.CppVtableFactory().create_all_vtables()

def create_vtables():
	phrank_containers.VtableFactory().create_all_vtables()

class VtableMaker(idaapi.action_handler_t):
	def __init__(self):
		super().__init__()
		self.factory = phrank_containers.VtableFactory()

	def activate(self, ctx):
		if ctx.widget_type != idaapi.BWN_PSEUDOCODE:
			return

		hx_view = idaapi.get_widget_vdui(ctx.widget)
		cfunc = hx_view.cfunc
		citem = hx_view.item
		if citem.citype != idaapi.VDI_EXPR:
			return 0

		expr = citem.it.to_specific_type

		parent_asg = expr
		while parent_asg is not None:
			if parent_asg.op == idaapi.cot_asg:
				break
			parent_asg = cfunc.body.find_parent_of(parent_asg).to_specific_type

		if parent_asg is None:
			return

		intval = phrank_hexrays.get_int(parent_asg.y)
		if intval is None:
			return 0

		vtbl = self.factory.create_vtable(addr=intval)
		if vtbl is None:
			print("failed to create vtable at", hex(intval))
		else:
			print("successfully created vtable", vtbl.get_name(), "at", hex(intval))
		return 1

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

idaapi.unregister_action("vtblmkr")

idaapi.register_action(
	idaapi.action_desc_t("vtblmkr", "make vtable", VtableMaker(), "Alt-Q")
)