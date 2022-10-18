import idautils
import idc

import phrank.util_aux as util_aux

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.containers.vtable import Vtable

class VtableAnalyzer(TypeAnalyzer):
	def __init__(self):
		super().__init__()
		self._addr2vtbl : dict[int, Vtable] = {}

	def get_vtable(self, vtable_ea):
		return self._addr2vtbl.get(vtable_ea)

	def create_vtable(self, addr, vtbl_funcs):
		vtbl_name = "vtable_" + hex(addr)[2:]
		vtbl_name = util_aux.get_next_available_strucname(vtbl_name)
		vtbl = Vtable(name=vtbl_name, vtbl_funcs=vtbl_funcs)
		self._addr2vtbl[addr] = vtbl
		return vtbl

	def analyze_gvar(self, gvar_ea):
		vtbl = self._addr2vtbl.get(gvar_ea)
		if vtbl is not None:
			return vtbl

		vfcs = Vtable.get_vtable_functions_at_addr(gvar_ea)
		if len(vfcs) == 0:
			return None

		return self.create_vtable(gvar_ea, vfcs)

	def analyze_everything(self):
		def find_candidates_in(ea_start, ea_end):
			ptr_size = util_aux.get_ptr_size()
			it_ea = ea_start
			while it_ea < ea_end:
				vfcs = Vtable.get_vtable_functions_at_addr(it_ea)
				if len(vfcs) == 0:
					it_ea += ptr_size
					continue
				yield it_ea, vfcs
				it_ea += len(vfcs) * ptr_size

		candidates = (
			(vea, vfcs)
			for segstart, segend in util_aux.iterate_segments()
			for vea, vfcs in find_candidates_in(segstart, segend)
		)
		for vtbl_ea, vtbl_funcs in candidates:
			vtbl = self.create_vtable(vtbl_ea, vtbl_funcs)
			self.new_types.append(vtbl)