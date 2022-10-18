import phrank.util_aux as util_aux

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.containers.vtable import Vtable

class VtableAnalyzer(TypeAnalyzer):
	def __init__(self):
		super().__init__()
		self._addr2vtbl : dict[int, Vtable] = {}

	def get_vtable(self, vtable_ea):
		return self._addr2vtbl.get(vtable_ea)

	def analyze_gvar(self, gvar_ea):
		vtbl = self._addr2vtbl.get(gvar_ea)
		if vtbl is not None:
			return vtbl

		vfcs = Vtable.get_vtable_functions_at_addr(gvar_ea)
		if len(vfcs) == 0:
			return None

		vtbl_name = "vtable_" + hex(gvar_ea)[2:]
		vtbl_name = util_aux.get_next_available_strucname(vtbl_name)
		vtbl = Vtable(name=vtbl_name, vtbl_funcs=vfcs)
		self._addr2vtbl[gvar_ea] = vtbl
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