from __future__ import annotations

import idc
import idaapi

from pyphrank.function_manager import FunctionManager
from pyphrank.ast_parts import Var, SExpr
import pyphrank.utils as utils


class TypeAnalyzer(FunctionManager):
	def __init__(self, cfunc_factory=None, ast_analyzer=None) -> None:
		super().__init__(cfunc_factory=cfunc_factory, ast_analyzer=ast_analyzer)

		# analysis context
		# analyzed types without actually changing types
		self.var2tinfo : dict[Var, idaapi.tinfo_t] = {}
		self.retval2tinfo : dict[int, idaapi.tinfo_t] = {}

		# analysis results
		self.new_types : set[int] = set() # created types
		self.new_xrefs : list[tuple[int,int]] = [] # created xrefs

	def get_original_var_type(self, var:Var) -> idaapi.tinfo_t:
		if var.is_local():
			return self.get_cfunc_lvar_type(var.func_ea, var.lvar_id)
		else:
			return utils.addr2tif(var.obj_ea)

	def set_var_type(self, var:Var, var_tinfo:idaapi.tinfo_t):
		self.var2tinfo[var] = var_tinfo

	def get_var_type(self, var:Var) -> idaapi.tinfo_t:
		return self.var2tinfo.get(var, utils.UNKNOWN_TYPE)

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
			if new_type_tif is utils.UNKNOWN_TYPE:
				continue

			if var.is_local():
				self.set_lvar_tinfo(var.func_ea, var.lvar_id, new_type_tif)
			else:
				rv = idc.SetType(var.obj_ea, str(new_type_tif) + ';')
				if rv == 0:
					utils.log_warn(f"setting {hex(var.obj_ea)} to {new_type_tif} failed")
		self.var2tinfo.clear()

		for frm, to in self.new_xrefs:
			rv = idaapi.add_cref(frm, to, idaapi.fl_CN)
			if not rv:
				utils.log_warn(f"failed to add code reference from {hex(frm)} to {hex(to)}")
		self.new_xrefs.clear()

		self.retval2tinfo.clear()

	def analyze_var(self, var:Var) -> idaapi.tinfo_t:
		raise NotImplementedError

	def analyze_retval(self, func_ea:int) -> idaapi.tinfo_t:
		raise NotImplementedError

	def analyze_sexpr_type(self, sexpr:SExpr) -> idaapi.tinfo_t:
		raise NotImplementedError