from __future__ import annotations

import idc
import idaapi

from phrank.function_manager import FunctionManager
from phrank.ast_parts import Var
import phrank.utils as utils


class TypeAnalyzer(FunctionManager):
	def __init__(self, func_factory=None) -> None:
		super().__init__(cfunc_factory=func_factory)

		# analysis context
		# analyzed types without actually changing types
		self.var2tinfo : dict[Var, idaapi.tinfo_t] = {}
		self.retval2tinfo : dict[int, idaapi.tinfo_t] = {}

		# analysis results
		self.new_types : set[int] = set()    # created types
		self.new_xrefs = []    # created xrefs

	def clear_analysis(self):
		# delete temporaly created new types
		for t in self.new_types:
			idc.del_struc(t)
		self.new_types.clear()

		self.new_xrefs.clear()
		self.var2tinfo.clear()
		self.retval2tinfo.clear()

	def apply_analysis(self):
		# new types are already created, simply skip them
		self.new_types.clear()

		for var, new_type_tif in self.var2tinfo.items():
			if new_type_tif is utils.UNKNOWN_TYPE: continue

			if var.is_local():
				self.set_lvar_tinfo(var.func_ea, var.lvar_id, new_type_tif)
			else:
				rv = idc.SetType(var.obj_ea, str(new_type_tif) + ';')
				if rv == 0:
					print("setting", hex(var.obj_ea), "to", new_type_tif, "failed")
		self.var2tinfo.clear()

		for frm, to in self.new_xrefs:
			rv = idaapi.add_cref(frm, to, idaapi.fl_CN)
			if not rv:
				print("WARNING: failed to add code reference from", hex(frm), "to", hex(to))
		self.new_xrefs.clear()

		self.retval2tinfo.clear()

	def analyze_everything(self):
		raise NotImplementedError

	def analyze_var(self, var:Var) -> idaapi.tinfo_t:
		raise NotImplementedError

	def analyze_retval(self, func_ea:int) -> idaapi.tinfo_t:
		raise NotImplementedError

	def analyze_sexpr_type(self, func_ea:int, cexpr:int) -> idaapi.tinfo_t:
		raise NotImplementedError

	def analyze_structure(self, struct):
		raise NotImplementedError

	def analyze_field(self, struct, offset):
		raise NotImplementedError