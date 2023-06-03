import idaapi
import pyphrank.utils as utils

from pyphrank.analyzers.type_analyzer import TypeAnalyzer
from pyphrank.ast_parts import Var
from pyphrank.containers.vtable import Vtable


class VtableAnalyzer(TypeAnalyzer):
	def create_vtable_at_address(self, addr:int):
		vfcs = Vtable.get_vtable_functions_at_addr(addr)
		if len(vfcs) == 0:
			return None

		vtbl_name = "vtable_" + hex(addr)[2:]
		vtbl_name = utils.get_next_available_strucname(vtbl_name)
		vtbl = Vtable.create(vtbl_name)
		if vtbl is None:
			return None

		unknown_func_ptr_tif = utils.str2tif("void*")
		for func_addr in vfcs:
			member_name = idaapi.get_name(func_addr)
			if member_name is None:
				member_name = "field_" + hex(vtbl.size)[2:]
				utils.log_warn(f"failed to get function name {hex(func_addr)}")

			member_name = utils.get_next_available_membername(vtbl.strucid, member_name, Vtable.REUSE_DELIM)

			func_ptr_tif = self.get_funcptr_tinfo(func_addr)
			if func_ptr_tif is utils.UNKNOWN_TYPE:
				func_ptr_tif = unknown_func_ptr_tif

			vtbl.append_member(member_name, func_ptr_tif, hex(func_addr))
		return vtbl

	def analyze_var(self, var:Var) -> idaapi.tinfo_t:
		if var.is_local():
			return utils.UNKNOWN_TYPE

		vtbl = self.var2tinfo.get(var)
		if vtbl is not None:
			return vtbl

		# trying to initialize from type at address
		if (vtbl := Vtable.get_vtable_at_address(var.obj_ea)) is not None:
			tif = vtbl.tinfo
		elif (vtbl := self.create_vtable_at_address(var.obj_ea)) is not None:
			tif = vtbl.tinfo
			self.new_types.add(vtbl.strucid)
		else:
			tif = utils.UNKNOWN_TYPE

		self.var2tinfo[var] = tif
		return tif