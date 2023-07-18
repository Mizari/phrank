from __future__ import annotations

import idaapi

import pyphrank.utils as utils

from pyphrank.ast_analyzer import CTreeAnalyzer, ASTAnalysis
from pyphrank.cfunction_factory import CFunctionFactory
from pyphrank.ast_parts import ASTCtx, Node, UNKNOWN_SEXPR

def get_funcname(func_ea: int) -> str:
	return idaapi.get_name(func_ea)


class FunctionManager:
	def __init__(self, cfunc_factory=None, ast_analyzer=None):
		if cfunc_factory is None:
			cfunc_factory = CFunctionFactory()
		self.func_factory = cfunc_factory

		if ast_analyzer is None:
			ast_analyzer = CTreeAnalyzer()
		self.ast_analyzer = ast_analyzer

	def get_ast_analysis(self, func_ea:int) -> ASTAnalysis:
		if not utils.is_func_start(func_ea):
			utils.log_warn(f"{hex(func_ea)} is not a function")

		cfunc = self.get_cfunc(func_ea)
		if cfunc is None:
			actx = ASTCtx.empty()
			nop_node = Node(Node.EXPR, UNKNOWN_SEXPR)
			analysis = ASTAnalysis(nop_node, actx)
		else:
			analysis = self.ast_analyzer.lift_cfunc(cfunc)
		return analysis

	def get_cfunc(self, func_ea:int) -> idaapi.cfunc_t|None:
		return self.func_factory.get_cfunc(func_ea)

	def get_func_details(self, func_ea: int):
		func_tinfo = self.get_func_tinfo(func_ea)
		if func_tinfo is None:
			return None

		func_details = idaapi.func_type_data_t()
		rv = func_tinfo.get_func_details(func_details)
		if not rv:
			utils.log_warn(f"failed to get func details in {get_funcname(func_ea)}")
			return None
		return func_details

	def get_cfunc_lvar_type(self, func_ea:int, var_id:int) -> idaapi.tinfo_t:
		func_tif = self.get_func_tinfo(func_ea)
		if func_tif is not None and var_id > func_tif.get_nargs():
			arg_type = func_tif.get_nth_arg(var_id)
			if not utils.is_tif_correct(arg_type):
				arg_type = utils.UNKNOWN_TYPE
			if arg_type is not utils.UNKNOWN_TYPE:
				return arg_type

		arg_type = self.get_arg_type(func_ea, var_id)
		if not utils.is_tif_correct(arg_type):
			arg_type = utils.UNKNOWN_TYPE
		if arg_type is not utils.UNKNOWN_TYPE:
			return arg_type

		cfunc = self.get_cfunc(func_ea)
		if cfunc is None:
			utils.log_warn(f"failed to get variable type, because of decompilation failure in {get_funcname(func_ea)}")
			return utils.UNKNOWN_TYPE

		if len(cfunc.lvars) <= var_id:
			print("ERROR:", "var id is too big.")
			return utils.UNKNOWN_TYPE

		var = cfunc.lvars[var_id]
		arg_type = var.type().copy()
		if not utils.is_tif_correct(arg_type):
			arg_type = utils.UNKNOWN_TYPE
		return arg_type

	def set_lvar_tinfo(self, func_ea:int, var_id:int, var_type:idaapi.tinfo_t):
		cfunc = self.get_cfunc(func_ea)
		if cfunc is None:
			utils.log_warn(f"failed to change variable type, because of decompilation failure in {get_funcname(func_ea)}")
			return

		var = cfunc.lvars[var_id]
		# var.set_user_type()
		# var.set_final_lvar_type(var_type)

		info = idaapi.lvar_saved_info_t()
		info.ll = var
		info.type = var_type
		info.name = var.name
		rv = idaapi.modify_user_lvar_info(func_ea, idaapi.MLI_TYPE, info)
		assert rv, "Failed to modify lvar"

		self.func_factory.clear_cfunc(func_ea)

	def get_cfunc_lvar(self, func_ea: int, lvar_id:int):
		cfunc = self.get_cfunc(func_ea)
		if cfunc is None:
			return None
		return cfunc.lvars[lvar_id]

	def get_arg_type(self, func_ea:int, arg_id:int) -> idaapi.tinfo_t:
		# XXX do not refactor this into one liner, 
		# XXX because ida will lose arg type somewhere along the way
		fdet = self.get_func_details(func_ea)
		if fdet is None:
			utils.log_warn(f"failed to get func details in {get_funcname(func_ea)}")
			return utils.UNKNOWN_TYPE

		if len(fdet) <= arg_id:
			return utils.UNKNOWN_TYPE
		return fdet[arg_id].type.copy()

	def set_arg_type(self, func_ea:int, arg_id:int, arg_type:idaapi.tinfo_t):
		if isinstance(arg_type, str):
			arg_type = utils.str2tif(arg_type)

		func_details = self.get_func_details(func_ea)
		if func_details is None:
			utils.log_warn(f"failed to change argument type (no func details) in {get_funcname(func_ea)}")
			return

		func_details[arg_id].type = arg_type.copy()

		new_func_tinfo = idaapi.tinfo_t()
		rv = new_func_tinfo.create_func(func_details)
		assert rv, "Failed to create func tinfo from details"

		rv = idaapi.apply_tinfo(func_ea, new_func_tinfo, 0)
		assert rv, "Failed to apply new tinfo to function"

		self.func_factory.clear_cfunc(func_ea)

	def get_func_tinfo(self, func_ea:int) -> idaapi.tinfo_t:
		tif = idaapi.tinfo_t()
		if idaapi.get_tinfo(tif, func_ea) and tif.is_correct():
			return tif

		cfunc = self.get_cfunc(func_ea)
		if cfunc is not None:
			cfunc.get_func_type(tif)
			if tif.is_correct():
				return tif

		if utils.is_movrax_ret(func_ea):
			rv = utils.str2tif("__int64 (*)()")
			return rv.copy()

		utils.log_warn(f"failed to get tinfo for {hex(func_ea)} {get_funcname(func_ea)}")
		return utils.UNKNOWN_TYPE

	def get_funcptr_tinfo(self, func_ea:int) -> idaapi.tinfo_t:
		tif = self.get_func_tinfo(func_ea)
		if tif is utils.UNKNOWN_TYPE:
			return utils.UNKNOWN_TYPE
		rv = tif.create_ptr(tif)
		if rv is False:
			utils.log_warn(f"failed to change tinfo of {str(tif)}")
			return utils.UNKNOWN_TYPE
		return tif

	def get_nargs(self, func_ea:int) -> int:
		tif = self.get_func_tinfo(func_ea)
		if tif is None:
			return 0
		return tif.get_nargs()

	def get_lvars_counter(self, func_ea:int) -> int:
		cfunc = self.get_cfunc(func_ea)
		if cfunc is None:
			return 0

		counter = 0
		for lv in cfunc.get_lvars():
			if lv.name == '':
				continue
			counter += 1
		return counter

	def get_lvar_name(self, func_ea:int, lvar_id:int) -> str:
		lvar = self.get_cfunc_lvar(func_ea, lvar_id)
		if lvar is None:
			return ""
		return lvar.name