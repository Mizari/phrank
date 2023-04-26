from __future__ import annotations

import idaapi

import phrank.utils as utils
from phrank.ast_analysis import *


def get_var(expr:idaapi.cexpr_t, actx:ASTCtx) -> Var|None:
	expr = utils.strip_casts(expr)
	if expr.op == idaapi.cot_var:
		return Var(actx.addr, expr.v.idx)
	if expr.op == idaapi.cot_obj and not utils.is_func_start(expr.obj_ea):
		return Var(expr.obj_ea)
	return None

def extract_vars(expr:idaapi.cexpr_t, actx:ASTCtx) -> set[Var]:
	v = get_var(expr, actx)
	if v is not None:
		return {v}
	vars = set()
	if expr.x is not None:
		vars.update(extract_vars(expr.x, actx))
	if expr.y is not None:
		vars.update(extract_vars(expr.y, actx))
	if expr.z is not None:
		vars.update(extract_vars(expr.z, actx))
	if expr.op == idaapi.cot_call:
		for a in expr.a:
			vars.update(extract_vars(a, actx))
	return vars

def get_var_use_chain(expr:idaapi.cexpr_t, actx:ASTCtx) -> VarUseChain|None:
	var = get_var(expr, actx)
	if var is not None:
		return VarUseChain(var)

	expr = utils.strip_casts(expr)
	if expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_helper:
		vuc = get_var_use_chain(expr.a[0], actx)
		if vuc is None:
			print("WARNING:", "unknown chain var use expression operand", expr.opname, utils.expr2str(expr))
			return None

		var, use_chain = vuc.var, vuc.uses

		helper2offset = {
			"HIBYTE": 1,
			"LOBYTE": 0,
			"HIWORD": 2,
			"LOWORD": 0,
		}
		offset = helper2offset.get(expr.x.helper)
		if offset is None:
			print("WARNING: unknown helper", expr.x.helper)
			return None
		if len(use_chain) != 0:
			print("WARNING: helper of non-variable expr", utils.expr2str(expr))

		var_use = VarUse(offset, VarUse.VAR_HELPER)
		use_chain.append(var_use)
		return VarUseChain(var, *use_chain)

	op2use_type = {
		idaapi.cot_ptr: VarUse.VAR_PTR,
		idaapi.cot_memptr: VarUse.VAR_PTR,
		idaapi.cot_memref: VarUse.VAR_ADD,
		idaapi.cot_ref: VarUse.VAR_ADD,
		idaapi.cot_idx: VarUse.VAR_PTR,
		idaapi.cot_add: VarUse.VAR_ADD,
		idaapi.cot_sub: VarUse.VAR_ADD,
	}
	use_type = op2use_type.get(expr.op)
	if use_type is None:
		print("WARNING:", "unknown chain var use expression operand", expr.opname, utils.expr2str(expr))
		return None

	vuc = get_var_use_chain(expr.x, actx)
	if vuc is None:
		return None

	var, use_chain = vuc.var, vuc.uses

	if expr.op in [idaapi.cot_ptr, idaapi.cot_ref]:
		offset = 0

	elif expr.op in [idaapi.cot_memptr, idaapi.cot_memref]:
		offset = expr.m

	elif expr.op in [idaapi.cot_idx, idaapi.cot_add, idaapi.cot_sub]:
		offset = utils.get_int(expr.y)
		if offset is None:
			print("WARNING:", "unknown expression add operand", utils.expr2str(expr.y))
			return None
		if expr.op == idaapi.cot_sub: offset = -offset
		if expr.x.type.is_ptr():
			pointed = expr.x.type.get_pointed_object()
			offset *= pointed.get_size()

	# this should not happen at all, since expr op is check when use_type gets got
	else:
		raise Exception("Wut")

	var_use = VarUse(offset, use_type)
	use_chain.append(var_use)
	return VarUseChain(var, *use_chain)


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
			# print("WARNING:", f"found multiple variables in {utils.expr2str(expr)}")
			return None

		vuc = get_var_use_chain(expr, actx)
		if vuc is None:
			# print("WARNING:", f"failed to calculate var use chain for {utils.expr2str(expr)}")
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