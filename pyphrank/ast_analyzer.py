from __future__ import annotations

import idaapi

import pyphrank.utils as utils
from pyphrank.ast_parts import SExpr, ASTCtx, CallCast, TypeCast
from pyphrank.ast_parts import Var, VarUse, VarUseChain, UNKNOWN_SEXPR
from pyphrank.ast_analysis import ASTAnalysis


bool_operations = {
	idaapi.cot_bor, idaapi.cot_uge, idaapi.cot_band, idaapi.cot_sge,
	idaapi.cot_sgt, idaapi.cot_eq, idaapi.cot_ne, idaapi.cot_slt,
	idaapi.cot_land, idaapi.cot_lnot, idaapi.cot_sle, idaapi.cot_ult,
	idaapi.cot_ule, idaapi.cot_lor, idaapi.cot_ugt,
}

binary_operations = {
	idaapi.cot_mul, idaapi.cot_sub,
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


class CTreeAnalyzer:
	def __init__(self):
		self.current_ast_analysis: ASTAnalysis = None # type:ignore
		self.ast_analysis_cache = {}

	def cache_analysis(self, analysis:ASTAnalysis):
		self.ast_analysis_cache[analysis.actx.addr] = analysis

	def get_ast_analysis(self, cfunc:idaapi.cfunc_t) -> ASTAnalysis:
		cached = self.ast_analysis_cache.get(cfunc.entry_ea)
		if cached is not None:
			return cached

		rv = self.lift_cfunc(cfunc)
		self.cache_analysis(rv)
		return rv

	def lift_cfunc(self, cfunc:idaapi.cfunc_t) -> ASTAnalysis:
		actx = ASTCtx.from_cfunc(cfunc)
		self.current_ast_analysis = ASTAnalysis(actx)
		self.lift_block(cfunc.body.cblock)
		rv, self.current_ast_analysis = self.current_ast_analysis, None # type:ignore
		return rv

	def lift_block(self, cblock):
		for instr in cblock:
			self.lift_instr(instr)

	def lift_instr(self, cinstr):
		if cinstr.op == idaapi.cit_expr:
			sexpr = self.lift_cexpr(cinstr.cexpr)
		elif cinstr.op == idaapi.cit_if:
			sexpr = self.lift_cexpr(cinstr.cif.expr)
			self.lift_block(cinstr.cif.ithen.cblock)
			if cinstr.cif.ielse is not None:
				self.lift_block(cinstr.cif.ielse.cblock)
		elif cinstr.op == idaapi.cit_for:
			init = self.lift_cexpr(cinstr.cfor.init)
			expr = self.lift_cexpr(cinstr.cfor.expr)
			step = self.lift_cexpr(cinstr.cfor.step)
			self.lift_block(cinstr.cfor.body.cblock)
		elif cinstr.op == idaapi.cit_while:
			self.lift_cexpr(cinstr.cwhile.expr)
			self.lift_block(cinstr.cwhile.body.cblock)
		elif cinstr.op == idaapi.cit_do:
			self.lift_cexpr(cinstr.cdo.expr)
			self.lift_block(cinstr.cdo.body.cblock)
		elif cinstr.op in (idaapi.cit_asm, idaapi.cit_empty, idaapi.cit_goto, idaapi.cit_end, idaapi.cit_break, idaapi.cit_continue):
			pass
		elif cinstr.op == idaapi.cit_return:
			sexpr = self.lift_cexpr(cinstr.creturn.expr)
			if sexpr.is_var_use_chain() and sexpr.var is None:
				self.current_ast_analysis.var_reads.append(sexpr.var_use_chain)

			self.current_ast_analysis.returns.append(sexpr)
		elif cinstr.op == idaapi.cit_switch:
			# cinstr.cswitch.cases + cinstr.cswitch.expr
			pass
		else:
			utils.log_err(f"unknown instr operand {cinstr.opname}")

	@property
	def actx(self) -> ASTCtx:
		return self.current_ast_analysis.actx

	def lift_cexpr(self, expr:idaapi.cexpr_t) -> SExpr:
		if expr.op == idaapi.cot_cast:
			expr = expr.x

		if expr.op == idaapi.cot_asg:
			target = self.lift_cexpr(expr.x)
			# dont add target var_use_chain to reads, because it is write
			# if its not var_use_chain, then it gets added to reads there

			# var_use_chain value IS a read though
			value = self.lift_cexpr(expr.y)
			if value.is_var_use_chain() and value.var is None:
				self.current_ast_analysis.var_reads.append(value.var_use_chain)
			asg = SExpr.create_assign(expr.ea, target, value)
			self.current_ast_analysis.assigns.append(asg)
			return UNKNOWN_SEXPR

		elif expr.op == idaapi.cot_call and expr.x.op != idaapi.cot_helper:
			call_func = self.lift_cexpr(expr.x)
			if call_func.is_var_use_chain() and call_func.var is None:
				self.current_ast_analysis.var_reads.append(call_func.var_use_chain)

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
				if arg_sexpr.is_var_use_chain() and arg_sexpr.var is None:
					self.current_ast_analysis.var_reads.append(arg_sexpr.var_use_chain)
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
			# TODO potential type casts of arg1 and arg2
			return UNKNOWN_SEXPR

		elif expr.op == idaapi.cot_num:
			return SExpr.create_int(expr.ea, expr.n._value, expr.type)

		elif expr.op == idaapi.cot_obj and utils.is_func_start(expr.obj_ea):
			return SExpr.create_function(expr.ea, expr.obj_ea)

		elif expr.op in bool_operations:
			return SExpr.create_bool_op(expr.ea)

		elif (vuc := get_var_use_chain(expr, self.actx)) is not None:
			return SExpr.create_var_use_chain(expr.ea, vuc)

		elif expr.op in rw_operations:
			# TODO not implemented
			return UNKNOWN_SEXPR

		elif expr.op in binary_operations and len(extract_vars(expr, self.actx)) > 1:
			x = self.lift_cexpr(expr.x)
			if x.is_var_use_chain() and x.var is None:
				self.current_ast_analysis.var_reads.append(x.var_use_chain)
			y = self.lift_cexpr(expr.y)
			if y.is_var_use_chain() and y.var is None:
				self.current_ast_analysis.var_reads.append(y.var_use_chain)
			return UNKNOWN_SEXPR

		utils.log_warn(f"failed to lift {expr.opname} {utils.expr2str(expr)} in {idaapi.get_name(self.actx.addr)}")
		return UNKNOWN_SEXPR