from __future__ import annotations

import idaapi

import phrank.utils as utils
from phrank.ast_analysis import *


class ASTAnalyzer(idaapi.ctree_visitor_t):
	def __init__(self):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
		self.current_ast_analysis: ASTAnalysis = None # type:ignore

	def analyze_cfunc(self, cfunc: idaapi.cfunc_t) -> ASTAnalysis:
		actx = ASTCtx.from_cfunc(cfunc)
		self.current_ast_analysis = ASTAnalysis(actx)
		self.apply_to(cfunc.body, None)

		rv, self.current_ast_analysis = self.current_ast_analysis, None # type:ignore
		return rv

	def visit_insn(self, insn: idaapi.cinsn_t) -> int:
		if insn.op == idaapi.cit_return and self.handle_return(insn):
			self.prune_now()
		return 0

	def get_var_use_chain(self, expr:idaapi.cexpr_t) -> VarUseChain|None:
		actx = self.current_ast_analysis.actx

		# FIXME
		if expr.op == idaapi.cot_num:
			return None

		if len(extract_vars(expr, actx)) > 1:
			print("WARNING:", f"found multiple variables in {utils.expr2str(expr)}")
			return None

		vuc = get_var_use_chain(expr, actx)
		if vuc is None:
			print("WARNING:", f"failed to calculate var use chain for {utils.expr2str(expr)}")
			return None
		return vuc

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
		retval = utils.strip_casts(insn.creturn.expr)

		if (vuc := self.get_var_use_chain(retval)) is None:
			return True

		var, uses = vuc.var, vuc.uses
		rw = ReturnWrapper(var, retval, *uses)
		self.current_ast_analysis.returns.append(rw)
		return True

	def handle_call(self, expr:idaapi.cexpr_t) -> bool:
		fc = FuncCall(expr)
		self.current_ast_analysis.calls.append(fc)
		if fc.is_implicit():
			fc.implicit_var_use_chain = self.get_var_use_chain(expr.x)

		for arg_id, arg in enumerate(expr.a):
			self.apply_to_exprs(arg, None)
			arg = utils.strip_casts(arg)
			if arg.op in [idaapi.cot_num, idaapi.cot_sizeof, idaapi.cot_call]:
				continue

			if (vuc := self.get_var_use_chain(arg)) is None:
				continue

			var, uses = vuc.var, vuc.uses
			cast = CallCast(var, arg_id, fc, *uses)
			self.current_ast_analysis.call_casts.append(cast)
		return True

	def handle_assignment(self, expr: idaapi.cexpr_t) -> bool:
		self.handle_expr(expr.y)

		if (vuc := self.get_var_use_chain(expr.x)) is None:
			return True

		var, uses = vuc.var, vuc.uses
		w = VarWrite(var, expr.y, *uses)
		self.current_ast_analysis.var_writes.append(w)
		return True

	def handle_expr(self, expr:idaapi.cexpr_t) -> bool:
		if (vuc := self.get_var_use_chain(expr)) is None:
			return True

		var, uses = vuc.var, vuc.uses
		r = VarRead(var, *uses)
		self.current_ast_analysis.var_reads.append(r)
		return True