import idautils
import idc

import phrank.phrank_util as p_util

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.containers.vtable import Vtable

class VtableAnalyzer(TypeAnalyzer):
	__instance = None
	def __new__(cls, *args, **kwargs):
		if VtableAnalyzer.__instance is not None:
			return VtableAnalyzer.__instance

		return super().__new__(cls, *args, **kwargs)

	def __init__(self):
		if VtableAnalyzer.__instance is not None:
			return

		super().__init__()
		VtableAnalyzer.__instance = self

		self._created_vtables : dict[int, Vtable] = {}
		self._min_vtbl_size = 2

	def clear_created_vtables(self):
		self._created_vtables.clear()

	def get_vtable(self, vtable_ea):
		return self._created_vtables.get(vtable_ea, None)

	def get_vtables(self):
		return list(self._created_vtables.values())

	def make_vtable(self, addr):
		vtbl = self._created_vtables.get(addr, None)
		if vtbl is not None:
			return vtbl
		
		vfcs = self.get_candidate_at(addr)
		if vfcs is None:
			return None

		return self.create_vtable(addr=addr, vtbl_vuncs=vfcs)

	def get_new_vtbl_name(self):
		vtbl_name = "vtable_" + str(len(self._created_vtables))
		vtbl_name = p_util.get_next_available_strucname(vtbl_name)
		return vtbl_name

	def new_vtable(self, *args, **kwargs):
		return Vtable(*args, **kwargs)

	def create_vtable(self, *args, **kwargs):
		vtbl_name = self.get_new_vtbl_name()
		kwargs["name"] = vtbl_name
		vtbl = self.new_vtable(*args, **kwargs)
		vtbl_ea = vtbl.get_ea()
		if vtbl_ea is not None:
			self._created_vtables[vtbl_ea] = vtbl
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
		ptr_size = p_util.get_ptr_size()
		it_ea = ea_start
		while it_ea < ea_end:
			vfcs = self.get_candidate_at(it_ea)
			if vfcs is None:
				it_ea += ptr_size
				continue
			yield it_ea, vfcs
			it_ea += len(vfcs) * ptr_size

	def create_all_vtables(self):
		for vtbl_ea, vtbl_funcs in self.find_all_candidates():
			vtbl = self.create_vtable(addr=vtbl_ea, vtbl_vuncs=vtbl_funcs)