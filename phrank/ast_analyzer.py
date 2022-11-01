from __future__ import annotations

import idaapi

from phrank.util_ast import *
from phrank.ast_analysis import ASTAnalysis


class ASTAnalyzer(idaapi.ctree_visitor_t):
	def __init__(self):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
		self.current_ast_analysis: ASTAnalysis|None = None

	def analyze_cfunc(self, cfunc: idaapi.cfunc_t) -> ASTAnalysis:
		self.current_ast_analysis = ASTAnalysis()
		self.apply_to(cfunc.body, None)

		for w in self.current_ast_analysis._var_writes:
			varid, offset = get_var_offset(w.val)
			if varid == -1:
				continue

			vid = w.varid
			if varid == vid:
				continue

			curr = self.current_ast_analysis._var_substitutes.get(vid, None)
			if curr is not None:
				print("[*] WARNING", "var", vid, "is already substituted with", curr[0], "overwriting")
			self.current_ast_analysis._var_substitutes[vid] = (varid, offset)

		rv, self.current_ast_analysis = self.current_ast_analysis, None
		return rv

	def visit_insn(self, insn):
		if insn.op == idaapi.cit_return and self.handle_return(insn):
			self.prune_now()
		return 0

	def visit_expr(self, expr):
		if expr.op == idaapi.cot_asg:
			should_prune = self.handle_assignment(expr)
		elif expr.op == idaapi.cot_call:
			should_prune = self.handle_call(expr)
		else:
			should_prune = self.handle_expr(expr)

		if should_prune:
			self.prune_now()

		return 0

	def handle_return(self, insn):
		self.current_ast_analysis._returns.append(ReturnWrapper(insn))
		return False

	def handle_call(self, expr):
		fc = FuncCall(call_expr=expr)
		self.current_ast_analysis._calls.append(fc)
		for arg in expr.a:
			self.apply_to_exprs(arg, None)
		return True

	def handle_assignment(self, expr):
		varid, offset = get_varptr_write_offset(expr.x)
		if varid != -1:
			w = VarPtrWrite(varid, expr.y, offset)
			self.current_ast_analysis._varptr_writes.append(w)

		else:
			varid = get_var_write(expr.x)
			if varid != -1:
				w = VarWrite(varid, expr.y)
				self.current_ast_analysis._var_writes.append(w)

			else:
				self.apply_to(expr.x, None)

		self.apply_to(expr.y, None)

		return True

	def handle_expr(self, expr):
		varid, offset = get_var_access(expr)
		if varid != -1:
			w = VarAccess(varid, offset)
			self.current_ast_analysis._var_accesses.append(w)
			return True

		return False