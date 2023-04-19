from __future__ import annotations

import idaapi

from phrank.ast_parts import *
from phrank.util_func import is_func_start
from phrank.util_tif import get_tif_member_name

ARRAY_FUNCS = {"qmemcpy", "memcpy", "strncpy", "memset", "memmove", "strncat", "strncmp"}
ARRAY_FUNCS.update(['_' + s for s in ARRAY_FUNCS])

WARRAY_FUNCS = {"wcsncat", "wcsncpy"}
WARRAY_FUNCS.update(['_' + s for s in WARRAY_FUNCS])

PRINTF_FUNCS = {"vsnprintf", "snprintf"}
PRINTF_FUNCS.update(['_' + s for s in PRINTF_FUNCS])

HELPER_FUNCS = {"LOWORD", "HIWORD", "LOBYTE"}



def strip_casts(expr:idaapi.cexpr_t) -> idaapi.cexpr_t:
	while expr.op == idaapi.cot_cast:
		expr = expr.x
	return expr

def _strip_casts(func):
	def wrapper(expr, *args, **kwargs):
		expr = strip_casts(expr)
		return func(expr, *args, **kwargs)
	return wrapper

@_strip_casts
def get_var(expr:idaapi.cexpr_t, actx:ASTCtx) -> Var|None:
	if expr.op == idaapi.cot_var:
		return Var(actx.addr, expr.v.idx)
	if expr.op == idaapi.cot_obj and not is_func_start(expr.obj_ea):
		return Var(expr.obj_ea)
	return None

@_strip_casts
def get_int(expr:idaapi.cexpr_t) -> int|None:
	if expr.op == idaapi.cot_ref and expr.x.op == idaapi.cot_obj:
		return expr.x.obj_ea

	if expr.op == idaapi.cot_obj:
		return expr.obj_ea

	if expr.op == idaapi.cot_num:
		return expr.n._value

	return None

def expr2str(expr:idaapi.cexpr_t, hide_casts=False) -> str:
	def e2s(e):
		return expr2str(e, hide_casts=hide_casts)

	if expr.op == idaapi.cot_call:
		c = expr.x
		if c.op == idaapi.cot_helper:
			call = c.helper
		elif c.op == idaapi.cot_obj:
			call = idaapi.get_name(c.obj_ea)
		else:
			call = e2s(c)
		args = [e2s(a) for a in expr.a]
		return call + "(" + ",".join(args) + ")"

	op2getter = {
		idaapi.cot_var: lambda e: "LVAR(" + str(e.v.idx) + ")",
		idaapi.cot_ptr: lambda e: "*(" + e2s(e.x) + ")",
		idaapi.cot_idx: lambda e: e2s(e.x) + "[" + e2s(e.y) + "]",
		idaapi.cot_memref: lambda e: e2s(e.x) + "." + get_tif_member_name(e.x.type, e.m),
		idaapi.cot_memptr: lambda e: e2s(e.x) + "->" + get_tif_member_name(e.x.type.get_pointed_object(), e.m),
		idaapi.cot_num: lambda e: str(e.n._value),
		idaapi.cot_cast: lambda e: "(" + str(e.type) + ")(" + e2s(e.x) + ")",
		idaapi.cot_add: lambda e: e2s(e.x) + "+" + e2s(e.y),
		idaapi.cot_sub: lambda e: e2s(e.x) + "-" + e2s(e.y),
		idaapi.cot_mul: lambda e: e2s(e.x) + "*" + e2s(e.y),
		idaapi.cot_postinc: lambda e: e2s(e.x) + "++",
		idaapi.cot_preinc: lambda e: "++" + e2s(e.x),
		idaapi.cot_ref: lambda e: "&" + e2s(e.x),
		idaapi.cot_obj: lambda e: idaapi.get_name(e.obj_ea),
		idaapi.cot_sizeof: lambda e: "sizeof(" + e2s(e.x) + ")",
		idaapi.cot_neg: lambda e: "-" + e2s(e.x),
		idaapi.cot_helper: lambda e: e.helper + "(" + e2s(e.x) + ")",
		idaapi.cot_tern: lambda e: e2s(e.x) + ":" + e2s(e.y) + "?" + e2s(e.z),
		idaapi.cot_ne: lambda e: e2s(e.x) + "!=" + e2s(e.y),
		idaapi.cot_band: lambda e: e2s(e.x) + "&" + e2s(e.y),
		idaapi.cot_asg: lambda e: e2s(e.x) + "=" + e2s(e.y),
	}
	if hide_casts:
		op2getter[idaapi.cot_cast] = lambda e: e2s(e.x)
	getter = op2getter.get(expr.op)
	if getter is not None:
		return getter(expr)

	if expr.x is not None and expr.y is not None:
		return expr.opname + '(' + e2s(expr.x) + ',' + e2s(expr.y) + ')'
	elif expr.x is not None:
		return expr.opname + '(' + e2s(expr.x) + ')'
	else:
		print("unknown op in e2s", expr.opname)
		return "UNKNOWN"

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
	vars_dict = {v.varid: v for v in vars}
	vars = set(vars_dict.values())
	return vars

def get_var_use_chain(expr:idaapi.cexpr_t, actx:ASTCtx) -> VarUseChain|None:
	var = get_var(expr, actx)
	if var is not None:
		return VarUseChain(var)

	expr = strip_casts(expr)
	if expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_helper:
		vuc = get_var_use_chain(expr.a[0], actx)
		if vuc is None:
			print("unknown chain var use expression operand", expr.opname, expr2str(expr))
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
			print("WARNING: helper of non-variable expr", expr2str(expr))

		var_use = VarUse(offset, VarUse.VAR_HELPER)
		use_chain.append(var_use)
		return VarUseChain(var, *use_chain)

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
		print("unknown chain var use expression operand", expr.opname, expr2str(expr))
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
		offset = get_int(expr.y)
		if offset is None:
			print("unknown expression add operand", expr2str(expr.y))
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