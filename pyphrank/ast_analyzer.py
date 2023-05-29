from __future__ import annotations

import idaapi

import pyphrank.utils as utils
from pyphrank.ast_parts import SExpr, ASTCtx, CallCast, TypeCast, VarWrite
from pyphrank.ast_parts import Var, VarUse, VarUseChain, UNKNOWN_SEXPR
from pyphrank.ast_analysis import ASTAnalysis


bool_operations = {
	idaapi.cot_bor, idaapi.cot_uge, idaapi.cot_band, idaapi.cot_sge,
	idaapi.cot_sgt, idaapi.cot_eq, idaapi.cot_ne, idaapi.cot_slt,
	idaapi.cot_land, idaapi.cot_lnot, idaapi.cot_sle, idaapi.cot_ult,
	idaapi.cot_ule, idaapi.cot_lor, idaapi.cot_ugt,
}

rw_operations = {
	idaapi.cot_postdec, idaapi.cot_predec, idaapi.cot_preinc,
	idaapi.cot_postinc, idaapi.cot_asgadd, idaapi.cot_asgmul,
	idaapi.cot_asgsub, idaapi.cot_asgbor,
}

helper2offset = {
	"HIBYTE": 1,
	"LOBYTE": 0,
	"HIWORD": 2,
	"LOWORD": 0,
	"HIDWORD": 4,
}


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

def get_var_helper(expr:idaapi.cexpr_t, actx:ASTCtx) -> VarUseChain|None:
	if expr.op != idaapi.cot_call or expr.x.op != idaapi.cot_helper or len(expr.a) != 1:
		return None
	if (offset := helper2offset.get(expr.x.helper)) is None:
		return None

	if (var := get_var(expr.a[0], actx)) is None:
		return None

	return VarUseChain(var, VarUse(offset, VarUse.VAR_HELPER))

def get_var_use_chain(expr:idaapi.cexpr_t, actx:ASTCtx) -> VarUseChain|None:
	# FIXME
	if expr.op == idaapi.cot_num:
		return None

	if (var := get_var(expr, actx)) is not None:
		return VarUseChain(var)

	if len(extract_vars(expr, actx)) != 1:
		return None

	expr = utils.strip_casts(expr)
	if (var_helper := get_var_helper(expr, actx)) is not None:
		return var_helper

	op2use_type = {
		idaapi.cot_ptr: VarUse.VAR_PTR,
		idaapi.cot_memptr: VarUse.VAR_PTR,
		idaapi.cot_memref: VarUse.VAR_REF,
		idaapi.cot_ref: VarUse.VAR_REF,
		idaapi.cot_idx: VarUse.VAR_PTR,
		idaapi.cot_add: VarUse.VAR_ADD,
		idaapi.cot_sub: VarUse.VAR_ADD,
	}
	use_type = op2use_type.get(expr.op)
	if use_type is None:
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
			return None
		if expr.op == idaapi.cot_sub:
			offset = -offset
		if expr.x.type.is_ptr():
			pointed = expr.x.type.get_pointed_object()
			offset *= pointed.get_size()

	# this should not happen at all, since expr op is check when use_type gets got
	else:
		raise Exception("Wut")

	var_use = VarUse(offset, use_type)
	use_chain.append(var_use)
	return VarUseChain(var, *use_chain)


class CTreeAnalyzer(idaapi.ctree_visitor_t):
	def __init__(self):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
		self.current_ast_analysis: ASTAnalysis = None # type:ignore
		self.ast_analysis_cache = {}

	def get_ast_analysis(self, cfunc:idaapi.cfunc_t) -> ASTAnalysis:
		func_ea = cfunc.entry_ea
		cached = self.ast_analysis_cache.get(func_ea)
		if cached is not None:
			return cached

		actx = ASTCtx.from_cfunc(cfunc)
		self.current_ast_analysis = ASTAnalysis(actx)
		self.apply_to(cfunc.body, None)

		rv, self.current_ast_analysis = self.current_ast_analysis, None # type:ignore
		self.ast_analysis_cache[func_ea] = rv
		return rv

	@property
	def actx(self) -> ASTCtx:
		return self.current_ast_analysis.actx

	def visit_insn(self, insn: idaapi.cinsn_t) -> int:
		if insn.op == idaapi.cit_return and self.handle_return(insn):
			self.prune_now()
		return 0

	def handle_return(self, insn:idaapi.cinsn_t) -> bool:
		retval = utils.strip_casts(insn.creturn.expr)

		if (vuc := get_var_use_chain(retval, self.actx)) is None:
			return True

		rw = SExpr.create_var_use_chain(retval.ea, vuc)
		self.current_ast_analysis.returns.append(rw)
		return True

	def visit_expr(self, expr: idaapi.cexpr_t) -> int:
		self.lift_cexpr(expr)
		self.prune_now()
		return 0

	def lift_cexpr(self, expr:idaapi.cexpr_t) -> SExpr:
		if expr.op == idaapi.cot_cast:
			expr = expr.x

		if expr.op == idaapi.cot_asg:
			target = self.lift_cexpr(expr.x)
			value = self.lift_cexpr(expr.y)
			w = VarWrite(target, value)
			self.current_ast_analysis.var_writes.append(w)
			return UNKNOWN_SEXPR

		elif expr.op == idaapi.cot_call and expr.x.op != idaapi.cot_helper:
			call_func = self.lift_cexpr(expr.x)
			if call_func.is_function():
				fc = SExpr.create_explicit_function(expr.ea, call_func.function)
				self.current_ast_analysis.calls.append(fc)
			elif call_func is UNKNOWN_SEXPR:
				fc = UNKNOWN_SEXPR
			else:
				fc = SExpr.create_implicit_function(expr.ea, call_func)
				self.current_ast_analysis.calls.append(fc)
			for arg_id, arg in enumerate(expr.a):
				arg = utils.strip_casts(arg)
				arg_sexpr = self.lift_cexpr(arg)
				call_cast = CallCast(arg_sexpr, arg_id, call_func)
				self.current_ast_analysis.call_casts.append(call_cast)
			return fc

		elif expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_helper and expr.x.helper == "memset":
			arg_sexpr = self.lift_cexpr(expr.a[0])
			n = utils.get_int(expr.a[2])
			if n is None:
				n = 1
			type_cast = TypeCast(arg_sexpr, utils.str2tif(f"char [{n}]"))
			self.current_ast_analysis.type_casts.append(type_cast)
			return UNKNOWN_SEXPR

		elif expr.op == idaapi.cot_num:
			return SExpr.create_int(expr.ea, expr.n._value, expr.type)

		elif expr.op == idaapi.cot_obj and utils.is_func_start(expr.obj_ea):
			return SExpr.create_function(expr.ea, expr.obj_ea)

		elif expr.op in bool_operations:
			return SExpr.create_bool_op(expr.ea)

		elif (vuc := get_var_use_chain(expr, self.actx)) is not None:
			r = SExpr.create_var_use_chain(expr.ea, vuc)
			self.current_ast_analysis.var_reads.append(r)
			return r

		elif expr.op in rw_operations:
			# TODO not implemented
			return UNKNOWN_SEXPR

		elif len(extract_vars(expr, self.actx)) > 1:
			# TODO not implemented
			return UNKNOWN_SEXPR

		utils.log_warn(f"failed to lift {expr.opname} {utils.expr2str(expr)} in {idaapi.get_name(self.actx.addr)}")
		return UNKNOWN_SEXPR