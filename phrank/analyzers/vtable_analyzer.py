import idaapi
import phrank.utils as utils

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.containers.vtable import Vtable

class VtableAnalyzer(TypeAnalyzer):
	def create_vtable_at_address(self, addr:int):
		vfcs = Vtable.get_vtable_functions_at_addr(addr)
		if len(vfcs) == 0:
			return None

		vtbl_name = "vtable_" + hex(addr)[2:]
		vtbl_name = utils.get_next_available_strucname(vtbl_name)
		vtbl = Vtable(struc_locator=vtbl_name)

		for func_addr in vfcs:
			member_name = idaapi.get_name(func_addr)
			if member_name is None:
				member_name = "field_" + hex(vtbl.get_size())[2:]
				print("Failed to get function name", hex(func_addr))

			member_name = vtbl.get_next_available_name(member_name, Vtable.REUSE_DELIM)

			func_ptr_tif = self.get_ptr_tinfo(func_addr)
			if func_ptr_tif is None:
				func_ptr_tif = utils.VOIDPTR_TIF.copy()

			vtbl.append_member(member_name, func_ptr_tif, hex(func_addr))
		return vtbl

	def get_gvar_vtable(self, gvar_ea):
		return Vtable.get_vtable_at_address(gvar_ea)

	def analyze_gvar(self, gvar_ea):
		vtbl = self.gvar2tinfo.get(gvar_ea)
		if vtbl is not None:
			return vtbl

		# trying to initialize from type at address
		vtbl = Vtable.get_vtable_at_address(gvar_ea)
		if vtbl is not None:
			tif = vtbl.get_tinfo()
			self.gvar2tinfo[gvar_ea] = tif
			return tif

		vtbl = self.create_vtable_at_address(gvar_ea)
		if vtbl is None:
			tif = utils.UNKNOWN_TYPE
		else:
			self.new_types.append(vtbl.strucid)
			tif = vtbl.get_tinfo()

		self.gvar2tinfo[gvar_ea] = tif
		return tif

	def analyze_everything(self):
		for segstart, segend in utils.iterate_segments():
			self.analyze_segment(segstart, segend)

	def analyze_segment(self, segstart, segend):
		ptr_size = utils.get_ptr_size()
		while segstart < segend:
			vtbl = self.analyze_gvar(segstart)
			if vtbl is None:
				segstart += ptr_size
			else:
				segstart += vtbl.get_size()