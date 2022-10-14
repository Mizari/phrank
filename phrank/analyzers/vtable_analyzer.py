import idautils
import idc

import phrank.util_aux as util_aux

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.containers.vtable import Vtable

class VtableAnalyzer(TypeAnalyzer):
	def __init__(self):
		super().__init__()

		self._addr2vtbl : dict[int, Vtable] = {}
		self._min_vtbl_size = 2

	def get_vtable(self, vtable_ea):
		return self._addr2vtbl.get(vtable_ea, None)

	def make_vtable(self, addr):
		vtbl = self._addr2vtbl.get(addr, None)
		if vtbl is not None:
			return vtbl
		
		vfcs = self.get_candidate_at(addr)
		if vfcs is None:
			return None

		return self.create_vtable(addr=addr, vtbl_vuncs=vfcs)

	def get_new_vtbl_name(self):
		vtbl_name = "vtable_" + str(len(self._addr2vtbl))
		vtbl_name = util_aux.get_next_available_strucname(vtbl_name)
		return vtbl_name

	def new_vtable(self, *args, **kwargs):
		return Vtable(*args, **kwargs)

	def create_vtable(self, *args, **kwargs):
		vtbl_name = self.get_new_vtbl_name()
		kwargs["name"] = vtbl_name
		vtbl = self.new_vtable(*args, **kwargs)
		vtbl_ea = vtbl.get_ea()
		if vtbl_ea is not None:
			self._addr2vtbl[vtbl_ea] = vtbl
		else:
			print("[*] WARNING", "created vtable without address", vtbl.get_name())
		return vtbl

	def find_all_candidates(self):
		for segea in idautils.Segments():
			segstart = idc.get_segm_start(segea)
			segend = idc.get_segm_end(segea)
			yield from self.find_candidates_at(segstart, segend)

	def get_candidate_at(self, addr):
		vfcs = Vtable.get_vtable_functions_at_addr(addr, minsize=self._min_vtbl_size)
		if len(vfcs) == 0:
			return None

		return vfcs

	def find_candidates_at(self, ea_start, ea_end):
		ptr_size = util_aux.get_ptr_size()
		it_ea = ea_start
		while it_ea < ea_end:
			vfcs = self.get_candidate_at(it_ea)
			if vfcs is None:
				it_ea += ptr_size
				continue
			yield it_ea, vfcs
			it_ea += len(vfcs) * ptr_size

	def analyze_everything(self):
		for vtbl_ea, vtbl_funcs in self.find_all_candidates():
			vtbl = self.create_vtable(addr=vtbl_ea, vtbl_vuncs=vtbl_funcs)
			self.new_types.append(vtbl)