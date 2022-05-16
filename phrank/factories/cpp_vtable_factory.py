
import phrank.phrank_util as p_util
import phrank.phrank_hexrays as p_hrays

from phrank.factories.vtable_factory import VtableFactory
from phrank.containers.cpp_vtable import CppVtable

class CppVtableFactory(VtableFactory):
	__instance = None
	def __new__(cls, *args, **kwargs):
		if CppVtableFactory.__instance is not None:
			return CppVtableFactory.__instance

		return super().__new__(cls, *args, **kwargs)

	def __init__(self):
		if CppVtableFactory.__instance is not None:
			return

		super().__init__()
		CppVtableFactory.__instance = self

	def downgrade_classless_vtables(self):
		vid = 0
		for vtbl in self._created_vtables.values():
			if vtbl.get_class() is not None:
				continue
			new_name = "vtable_" + str(vid)
			new_name = p_util.get_next_available_strucname(new_name)
			vtbl.rename(new_name)
			vid += 1

	def get_candidate_at(self, addr):
		vfcs = super().get_candidate_at(addr)
		if vfcs is None:
			return None

		def get_n_callers(func, vea):
			fav : p_hrays.FuncAnalysisVisitor = p_hrays.FuncAnalysisVisitor.create(addr=func)
			return len([w for w in fav.get_writes_into_var(0, val=vea)])

		callers = p_util.get_func_calls_to(addr)
		if any([get_n_callers(f, addr) != 0 for f in callers]):
			return vfcs
		return None

	def get_new_vtbl_name(self):
		vtbl_name = "cpp_vtable_" + str(len(self._created_vtables))
		vtbl_name = p_util.get_next_available_strucname(vtbl_name)
		return vtbl_name

	def new_vtable(self, *args, **kwargs):
		return CppVtable(*args, **kwargs)