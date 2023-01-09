from __future__ import annotations

import idaapi

from phrank.ast_parts import *
from phrank.util_func import is_func_start

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
def get_var_assign(expr:idaapi.cexpr_t, actx:ASTCtx) -> Var|None:
	var = get_var(expr, actx)
	if var is not None:
		return var

	if expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_helper:
		func = expr.x.helper
		if func in HELPER_FUNCS:
			return get_var(expr.a[0], actx)

	if expr.op == idaapi.cot_ptr and expr.x.op == idaapi.cot_cast and expr.x.x.op == idaapi.cot_ref:
		return get_var(expr.x.x.x, actx)

	return None

@_strip_casts
def get_var_read(expr:idaapi.cexpr_t, actx:ASTCtx) -> tuple[Var|None,int]:
	if expr.op == idaapi.cot_memptr:
		return get_var(expr.x, actx), expr.m + expr.x.type.get_size()

	if expr.op == idaapi.cot_idx and expr.y.op == idaapi.cot_num:
		var = get_var(expr.x, actx)
		return var, (expr.y.n._value + 1) * expr.x.type.get_size()

	if expr.op == idaapi.cot_ptr:
		return get_var_offset(expr.x, actx)

	return None, -1

# not found is (None, any_int)
def get_var_ptr_write(expr:idaapi.cexpr_t, actx:ASTCtx) -> tuple[Var|None,int]:
	if expr.op == idaapi.cot_idx and expr.y.op == idaapi.cot_num:
		return get_var(expr.x, actx), expr.y.n._value * expr.x.type.get_size()

	if expr.op == idaapi.cot_ptr:
		return get_var_offset(expr.x, actx)

	if expr.op == idaapi.cot_memptr:
		return get_var(expr.x, actx), expr.m

	return None, -1

def get_var_struct_write(expr:idaapi.cexpr_t, actx:ASTCtx) -> tuple[Var|None,int]:
	if expr.op != idaapi.cot_memref:
		return None, -1

	offset = 0
	while expr.op == idaapi.cot_memref:
		offset += expr.m
		expr = expr.x
	return get_var(expr, actx), offset

# trying to get various forms of "var + X", where X is int
# not found is (None, any_int)
@_strip_casts
def get_var_offset(expr:idaapi.cexpr_t, actx:ASTCtx) -> tuple[Var|None, int]:
	var = get_var(expr, actx)
	if var is not None:
		return var, 0

	# form ((CASTTYPE*)var) + N
	elif expr.op in [idaapi.cot_add, idaapi.cot_sub] and expr.y.op == idaapi.cot_num:
		offset = expr.y.n._value
		if expr.op == idaapi.cot_sub:
			offset = - offset

		op_x = expr.x
		var = get_var(op_x, actx)

		if op_x.type.is_ptr():
			sz = op_x.type.get_pointed_object().get_size()
			if sz == idaapi.BADSIZE: 
				raise BaseException("Failed to get object's size")
			offset = offset * sz

		return var, offset

	else:
		return None, -1

@_strip_casts
def get_int(expr:idaapi.cexpr_t) -> int|None:
	if expr.op == idaapi.cot_ref and expr.x.op == idaapi.cot_obj:
		return expr.x.obj_ea

	if expr.op == idaapi.cot_obj:
		return expr.obj_ea

	if expr.op == idaapi.cot_num:
		return expr.n._value

	return None

def expr2str(expr:idaapi.cexpr_t):
	op2getter = {
		idaapi.cot_var: lambda e: "LVAR(" + str(e.v.idx) + ")",
		idaapi.cot_ptr: lambda e: "*(" + expr2str(e.x) + ")",
		idaapi.cot_idx: lambda e: expr2str(e.x) + "[" + expr2str(e.y) + "]",
		idaapi.cot_memref: lambda e: "MEMREF(" + expr2str(e.x) + "," + str(e.m) + ")",
		idaapi.cot_memptr: lambda e: "MEMPTR(" + expr2str(e.x) + "," + str(e.m) + ")",
		idaapi.cot_num: lambda e: str(e.n._value),
		idaapi.cot_cast: lambda e: "(" + str(e.type) + ")(" + expr2str(e.x) + ")",
		idaapi.cot_add: lambda e: expr2str(e.x) + "+" + expr2str(e.y),
		idaapi.cot_sub: lambda e: expr2str(e.x) + "-" + expr2str(e.y),
		idaapi.cot_mul: lambda e: expr2str(e.x) + "*" + expr2str(e.y),
		idaapi.cot_postinc: lambda e: expr2str(e.x) + "++",
		idaapi.cot_preinc: lambda e: "++" + expr2str(e.x),
		idaapi.cot_ref: lambda e: "&" + expr2str(e.x),
		idaapi.cot_obj: lambda e: idaapi.get_name(e.obj_ea),
		idaapi.cot_sizeof: lambda e: "sizeof(" + expr2str(e.x) + ")",
		idaapi.cot_neg: lambda e: "-" + expr2str(e.x),
		idaapi.cot_helper: lambda e: e.helper + "(" + expr2str(e.x) + ")",
		idaapi.cot_tern: lambda e: expr2str(e.x) + ":" + expr2str(e.y) + "?" + expr2str(e.z),
		idaapi.cot_ne: lambda e: expr2str(e.x) + "!=" + expr2str(e.y),
		idaapi.cot_band: lambda e: expr2str(e.x) + "&" + expr2str(e.y),
	}
	if expr.op == idaapi.cot_call:
		c = expr.x
		if c.op == idaapi.cot_helper:
			call = c.helper
		elif c.op == idaapi.cot_obj:
			call = idaapi.get_name(c.obj_ea)
		else:
			call = expr2str(c)
		args = [expr2str(a) for a in expr.a]
		return call + "(" + ",".join(args) + ")"

	getter = op2getter.get(expr.op)
	if getter is None:
		print("unknown op in expr2str", expr.opname)
		return "UNKNOWN"
	return getter(expr)

def extract_vars(expr:idaapi.cexpr_t, actx:ASTCtx):
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

def get_var_use_chain(expr:idaapi.cexpr_t, actx:ASTCtx):
	var = get_var(expr, actx)
	if var is not None:
		return var, []

	expr = strip_casts(expr)

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
		return None, []

	var, use_chain = get_var_use_chain(expr.x, actx)
	if var is None:
		return var, use_chain

	if expr.op in [idaapi.cot_ptr, idaapi.cot_ref]:
		offset = 0

	elif expr.op in [idaapi.cot_memptr, idaapi.cot_memref]:
		offset = expr.m

	elif expr.op in [idaapi.cot_idx, idaapi.cot_add, idaapi.cot_sub]:
		offset = get_int(expr.y)
		if offset is None:
			print("unknown expression add operand", expr2str(expr.y))
			return None, []
		if expr.x.type.is_ptr():
			pointed = expr.x.type.get_pointed_object()
			offset *= pointed.get_size()

	# this should not happen at all, since expr op is check when use_type gets got
	else:
		raise Exception("Wut")

	if expr.op == idaapi.cot_sub: offset = -offset

	var_use = VarUse(var, offset, use_type)
	use_chain.append(var_use)
	return var, use_chain