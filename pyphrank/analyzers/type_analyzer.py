from __future__ import annotations

import idc
import idaapi

from pyphrank.function_manager import FunctionManager
from pyphrank.ast_parts import Var, SExpr
from pyphrank.container_manager import ContainerManager
import pyphrank.utils as utils


class TypeAnalyzer(FunctionManager):
	def __init__(self, cfunc_factory=None, ast_analyzer=None) -> None:
		super().__init__(cfunc_factory=cfunc_factory, ast_analyzer=ast_analyzer)
		self.container_manager = ContainerManager()

		self.var2tinfo : dict[Var, idaapi.tinfo_t] = {}
		self.retval2tinfo : dict[int, idaapi.tinfo_t] = {}
		self.new_xrefs : list[tuple[int,int]] = []

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
		self.container_manager.delete_containers()

		self.new_xrefs.clear()
		self.var2tinfo.clear()
		self.retval2tinfo.clear()

	def apply_analysis(self):
		# new types are already created, simply skip them
		self.container_manager.clear()

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