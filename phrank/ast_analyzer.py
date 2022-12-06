from __future__ import annotations

import idaapi

import phrank.utils as utils
from phrank.ast_analysis import *


class ASTAnalyzer(idaapi.ctree_visitor_t):
	def __init__(self):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
		self.current_ast_analysis: ASTAnalysis|None = None

	def analyze_cfunc(self, cfunc: idaapi.cfunc_t) -> ASTAnalysis:
		self.current_ast_analysis = ASTAnalysis()
		self.apply_to(cfunc.body, None)

		for w in self.current_ast_analysis._lvar_writes:
			varid, offset = utils.get_lvar_offset(w.val)
			if varid == -1:
				continue

			vid = w.varid
			if varid == vid:
				continue

			curr = self.current_ast_analysis._lvar_substitutes.get(vid, None)
			if curr is not None:
				print("[*] WARNING", "var", vid, "is already substituted with", curr[0], "overwriting")
			self.current_ast_analysis._lvar_substitutes[vid] = (varid, offset)

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
		self.apply_to(expr.y, None)

		lvarid, offset = utils.get_lvarptr_write_offset(expr.x)
		if lvarid != -1:
			w = LvarPtrWrite(lvarid, expr.y, offset)
			self.current_ast_analysis._lvarptr_writes.append(w)
			return True

		lvarid = utils.get_lvar_write(expr.x)
		if lvarid != -1:
			w = LvarWrite(lvarid, expr.y)
			self.current_ast_analysis._lvar_writes.append(w)
			return True

		gvarid = utils.get_gvar_assign(expr.x)
		if gvarid != -1:
			w = GvarAssign(gvarid, expr.y)
			self.current_ast_analysis._gvar_assigns.append(w)
			return True

		gvarid, offset = utils.get_gvar_write(expr.x)
		if gvarid != -1:
			w = GvarWrite(gvarid, expr.y, offset)
			self.current_ast_analysis._gvar_writes.append(w)
			return True

		self.apply_to(expr.x, None)
		return True

	def handle_expr(self, expr):
		varid, offset = utils.get_lvar_access(expr)
		if varid != -1:
			w = LvarAccess(varid, offset)
			self.current_ast_analysis._lvar_accesses.append(w)
			return True

		return False