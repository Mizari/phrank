import idaapi

import phrank.util_aux as util_aux

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.containers.vtable import Vtable

class VtableAnalyzer(TypeAnalyzer):
	def get_gvar_vtable(self, gvar_ea):
		vtbl_strucid = self.get_gvar_strucid(gvar_ea)
		if vtbl_strucid != idaapi.BADADDR and Vtable.is_vtable(vtbl_strucid):
			return Vtable(gvar_ea, vtbl_strucid)
		return None

	def analyze_gvar(self, gvar_ea):
		vtbl = self.get_gvar_vtable(gvar_ea)
		if vtbl is not None:
			return vtbl

		vfcs = Vtable.get_vtable_functions_at_addr(gvar_ea)
		if len(vfcs) == 0:
			return None

		vtbl_name = "vtable_" + hex(gvar_ea)[2:]
		vtbl_name = util_aux.get_next_available_strucname(vtbl_name)
		vtbl = Vtable(name=vtbl_name, vtbl_funcs=vfcs)
		self.gvar2type[gvar_ea] = vtbl
		self.new_types.append(vtbl)
		return vtbl

	def analyze_everything(self):
		for segstart, segend in util_aux.iterate_segments():
			self.analyze_segment(segstart, segend)

	def analyze_segment(self, segstart, segend):
		ptr_size = util_aux.get_ptr_size()
		while segstart < segend:
			vtbl = self.analyze_gvar(segstart)
			if vtbl is None:
				segstart += ptr_size
			else:
				segstart += vtbl.get_size()