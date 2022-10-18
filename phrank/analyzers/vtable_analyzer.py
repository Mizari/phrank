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

	def make_vtable(self, addr):
		vtbl = self._addr2vtbl.get(addr)
		if vtbl is not None:
			return vtbl

		vfcs = Vtable.get_vtable_functions_at_addr(addr)
		if len(vfcs) == 0:
			return None

		return self.create_vtable(addr, vtbl_funcs=vfcs)

	def get_new_vtbl_name(self):
		vtbl_name = "vtable_" + str(len(self._addr2vtbl))
		vtbl_name = util_aux.get_next_available_strucname(vtbl_name)
		return vtbl_name

	def create_vtable(self, addr, vtbl_funcs=None):
		vtbl_name = self.get_new_vtbl_name()
		vtbl = Vtable(name=vtbl_name, vtbl_funcs=vtbl_funcs)
		self._addr2vtbl[addr] = vtbl
		return vtbl

	def find_all_candidates(self):
		for segea in idautils.Segments():
			segstart = idc.get_segm_start(segea)
			segend = idc.get_segm_end(segea)
			yield from self.find_candidates_in(segstart, segend)

	def find_candidates_in(self, ea_start, ea_end):
		ptr_size = util_aux.get_ptr_size()
		it_ea = ea_start
		while it_ea < ea_end:
			vfcs = Vtable.get_vtable_functions_at_addr(it_ea)
			if len(vfcs) == 0:
				it_ea += ptr_size
				continue
			yield it_ea, vfcs
			it_ea += len(vfcs) * ptr_size

	def analyze_everything(self):
		for vtbl_ea, vtbl_funcs in self.find_all_candidates():
			vtbl = self.create_vtable(vtbl_ea, vtbl_vuncs=vtbl_funcs)
			self.new_types.append(vtbl)