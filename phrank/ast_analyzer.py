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
		if fc.is_implicit():
			if len(utils.extract_vars(expr.x)) == 1:
				fc.implicit_var_use_chain = utils.get_var_use_chain(expr.x)
			else:
				print("Failed to get var use chain of implicit call for", utils.expr2str(expr.x))

		for arg_id, arg in enumerate(expr.a):
			self.apply_to_exprs(arg, None)
			arg = utils.strip_casts(arg)
			op = arg.op
			if op in [idaapi.cot_num, idaapi.cot_sizeof, idaapi.cot_call]:
				continue

			var, offset = utils.get_var_offset(arg)
			if var is not None:
				cast = CallCast(var, offset, CallCast.VAR_CAST, arg_id, fc)
				self.current_ast_analysis.call_casts.append(cast)
				continue

			var, offset = utils.get_var_ptr_write(arg)
			if var is not None:
				cast = CallCast(var, offset, CallCast.PTR_CAST, arg_id, fc)
				self.current_ast_analysis.call_casts.append(cast)
				continue

			self.current_ast_analysis.unknown_casts.append(arg)
		return True

	def handle_assignment(self, expr: idaapi.cexpr_t) -> bool:
		self.apply_to(expr.y, None)

		if len(utils.extract_vars(expr.x)) > 1:
			print("Found multiple variables in write target", utils.expr2str(expr.x))
			return True

		v, ch = utils.get_var_use_chain(expr.x)
		if v is None:
			print("Failed to calculate write target chain", utils.expr2str(expr.x))
			return True

		if len(ch) == 0:
			w = VarAssign(v, expr.y)
			self.current_ast_analysis.var_assigns.append(w)
			return True
		
		w = VarWrite(v, expr.y, ch)
		self.current_ast_analysis.var_writes.append(w)
		return True

	def handle_expr(self, expr:idaapi.cexpr_t) -> bool:
		var, offset = utils.get_var_read(expr)
		if var is not None:
			w = VarRead(var, offset)
			self.current_ast_analysis.lvar_reads.append(w)
			return True

		return False