
import phrank.util_aux as util_aux

from phrank.analyzers.vtable_analyzer import VtableAnalyzer
from phrank.containers.cpp_vtable import CppVtable

class CppVtableAnalyzer(VtableAnalyzer):
	def __init__(self):
		super().__init__()

	def downgrade_classless_vtables(self):
		vid = 0
		for vtbl in self._addr2vtbl.values():
			if vtbl.get_class() is not None:
				continue
			new_name = "vtable_" + str(vid)
			new_name = util_aux.get_next_available_strucname(new_name)
			vtbl.rename(new_name)
			vid += 1

	def get_candidate_at(self, addr):
		vfcs = super().get_candidate_at(addr)
		if vfcs is None:
			return None

		def get_n_callers(func, vea):
			fav = self.get_ast_analysis(func)
			return len([w for w in fav.get_writes_into_var(0, val=vea)])

		callers = util_aux.get_func_calls_to(addr)
		if any([get_n_callers(f, addr) != 0 for f in callers]):
			return vfcs
		return None

	def get_new_vtbl_name(self):
		vtbl_name = "cpp_vtable_" + str(len(self._addr2vtbl))
		vtbl_name = util_aux.get_next_available_strucname(vtbl_name)
		return vtbl_name

	def new_vtable(self, *args, **kwargs):
		return CppVtable(*args, **kwargs)