from __future__ import annotations

import idaapi

import phrank.utils as utils
from phrank.ast_analysis import *


class ASTAnalyzer(idaapi.ctree_visitor_t):
	def __init__(self):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
		self.current_ast_analysis: ASTAnalysis = ASTAnalysis()

	def analyze_cfunc(self, cfunc: idaapi.cfunc_t) -> ASTAnalysis:
		self.current_func_ea = cfunc.entry_ea
		self.apply_to(cfunc.body, None)

		rv, self.current_ast_analysis = self.current_ast_analysis, ASTAnalysis()
		return rv

	def visit_insn(self, insn: idaapi.cinsn_t) -> int:
		if insn.op == idaapi.cit_return and self.handle_return(insn):
			self.prune_now()
		return 0

	def visit_expr(self, expr: idaapi.cexpr_t) -> int:
		if expr.op == idaapi.cot_asg:
			should_prune = self.handle_assignment(expr)
		elif expr.op == idaapi.cot_call:
			should_prune = self.handle_call(expr)
		else:
			should_prune = self.handle_expr(expr)

		if should_prune:
			self.prune_now()

		return 0

	def handle_return(self, insn:idaapi.cinsn_t) -> bool:
		self.current_ast_analysis.returns.append(ReturnWrapper(insn))
		return False

	def handle_call(self, expr:idaapi.cexpr_t) -> bool:
		fc = FuncCall(expr)
		for arg_id, arg in enumerate(expr.a):
			self.apply_to_exprs(arg, None)
			arg = utils.strip_casts(arg)
			op = arg.op
			if op in [idaapi.cot_num, idaapi.cot_sizeof, idaapi.cot_call]:
				continue

			lvar_id, offset = utils.get_lvar_offset(arg)
			if lvar_id != -1:
				var = Var(Var.LOCAL_VAR, lvar_id)
				cast = CallCast(var, offset, CallCast.VAR_CAST, arg_id, fc)
				self.current_ast_analysis.call_casts.append(cast)
				continue

			lvar_id, offset = utils.get_lvar_ptr_write(arg)
			if lvar_id != -1:
				var = Var(Var.LOCAL_VAR, lvar_id)
				cast = CallCast(var, offset, CallCast.PTR_CAST, arg_id, fc)
				self.current_ast_analysis.call_casts.append(cast)
				continue

			obj_ea, offset = utils.get_gvar_offset(arg)
			if obj_ea != -1:
				if utils.is_func_start(obj_ea):
					continue

				var = Var(Var.GLOBAL_VAR, obj_ea)
				cast = CallCast(var, offset, CallCast.VAR_CAST, arg_id, fc)
				self.current_ast_analysis.call_casts.append(cast)
				continue

			obj_ea, offset = utils.get_gvar_ptr_write(arg)
			if obj_ea != -1:
				if utils.is_func_start(obj_ea):
					continue

				var = Var(Var.GLOBAL_VAR, obj_ea)
				cast = CallCast(var, offset, CallCast.PTR_CAST, arg_id, fc)
				self.current_ast_analysis.call_casts.append(cast)
				continue

			self.current_ast_analysis.unknown_casts.append(arg)
		return True

	def handle_assignment(self, expr: idaapi.cexpr_t) -> bool:
		self.apply_to(expr.y, None)

		lvarid, offset = utils.get_lvar_ptr_write(expr.x)
		if lvarid != -1:
			var = Var(Var.LOCAL_VAR, lvarid)
			w = VarWrite(var, expr.y, offset, VarWrite.PTR_WRITE)
			self.current_ast_analysis.lvar_writes.append(w)
			return True

		lvarid, offset = utils.get_lvar_struct_write(expr.x)
		if lvarid != -1:
			var = Var(Var.LOCAL_VAR, lvarid)
			w = VarWrite(var, expr.y, offset, VarWrite.STRUCT_WRITE)
			self.current_ast_analysis.lvar_writes.append(w)
			return True

		var = utils.get_var_assign(expr.x)
		if var is not None:
			w = VarAssign(var, expr.y)
			if var.is_local():
				self.current_ast_analysis.lvar_assigns.append(w)
			else:
				self.current_ast_analysis.gvar_assigns.append(w)
			return True

		gvarid, offset = utils.get_gvar_ptr_write(expr.x)
		if gvarid != -1:
			var = Var(Var.GLOBAL_VAR, gvarid)
			w = VarWrite(var, expr.y, offset, VarWrite.PTR_WRITE)
			self.current_ast_analysis.gvar_writes.append(w)
			return True

		gvarid, offset = utils.get_gvar_struct_write(expr.x)
		if gvarid != -1:
			var = Var(Var.GLOBAL_VAR, gvarid)
			w = VarWrite(var, expr.y, offset, VarWrite.STRUCT_WRITE)
			self.current_ast_analysis.gvar_writes.append(w)
			return True

		self.current_ast_analysis.unknown_asgs.append(expr.x)
		self.apply_to(expr.x, None)
		return True

	def handle_expr(self, expr:idaapi.cexpr_t) -> bool:
		lvarid, offset = utils.get_lvar_read(expr)
		if lvarid != -1:
			var = Var(Var.LOCAL_VAR, lvarid)
			w = VarRead(var, offset)
			self.current_ast_analysis.lvar_reads.append(w)
			return True

		return False