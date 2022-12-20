from __future__ import annotations

import idaapi

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
	def wrapper(expr):
		expr = strip_casts(expr)
		return func(expr)
	return wrapper

def get_lvar_assign(expr:idaapi.cexpr_t) -> int:
	if expr.op == idaapi.cot_var:
		return expr.v.idx

	if expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_helper:
		func = expr.x.helper
		if func in HELPER_FUNCS:
			arg0 = expr.a[0]
			if arg0.op == idaapi.cot_var:
				return arg0.v.idx

	if expr.op == idaapi.cot_ptr and expr.x.op == idaapi.cot_cast:
		if expr.x.x.op == idaapi.cot_ref and expr.x.x.x.op == idaapi.cot_var:
			return expr.x.x.x.v.idx

	return -1

@_strip_casts
def get_lvar_read(expr:idaapi.cexpr_t) -> tuple[int,int]:
	if expr.op == idaapi.cot_memptr and expr.x.op == idaapi.cot_var:
		return expr.x.v.idx, expr.m + expr.x.type.get_size()

	if expr.op == idaapi.cot_idx:
		if expr.x.op != idaapi.cot_var or expr.y.op != idaapi.cot_num:
			return -1, None

		return expr.x.v.idx, (expr.y.n._value + 1) * expr.x.type.get_size()

	if expr.op == idaapi.cot_ptr:
		return get_lvar_offset(expr.x)

	return -1, None

@_strip_casts
def get_gvar_assign(expr:idaapi.cexpr_t) -> int:
	if expr.op == idaapi.cot_obj:
		return expr.obj_ea

	if expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_helper:
		func = expr.x.helper
		if func in HELPER_FUNCS:
			arg0 = expr.a[0]
			if arg0.op == idaapi.cot_obj:
				return expr.obj_ea

	if expr.op == idaapi.cot_ptr and expr.x.op == idaapi.cot_cast:
		if expr.x.x.op == idaapi.cot_ref and expr.x.x.x.op == idaapi.cot_obj:
			return expr.x.x.x.obj_ea

	return -1

def get_gvar_ptr_write(expr:idaapi.cexpr_t) -> tuple[int,int]:
	if expr.op == idaapi.cot_idx:
		if expr.x.op != idaapi.cot_obj or expr.y.op != idaapi.cot_num:
			return -1, None

		return expr.x.obj_ea, expr.y.n._value * expr.x.type.get_size()

	if expr.op == idaapi.cot_ptr:
		return get_gvar_offset(expr.x)

	if expr.op == idaapi.cot_memptr and expr.x.op == idaapi.cot_obj:
		return expr.x.obj_ea, expr.m

	return -1, None

def get_gvar_struct_write(expr:idaapi.cexpr_t) -> tuple[int,int]:
	if expr.op != idaapi.cot_memref:
		return -1, None

	offset = 0
	while expr.op == idaapi.cot_memref:
		offset += expr.m
		expr = expr.x
	if expr.op == idaapi.cot_obj:
		return expr.obj_ea, offset
	return -1, None

# trying to get various forms of "var + X", where X is int

def get_gvar_read(expr):
	return -1, None

# not found is (-1, None) since there are no such local variables
# with negative id, and there CAN be negative offset
def get_lvar_ptr_write(expr:idaapi.cexpr_t) -> tuple[int,int]:
	if expr.op == idaapi.cot_idx:
		if expr.x.op != idaapi.cot_var or expr.y.op != idaapi.cot_num:
			return -1, None

		return expr.x.v.idx, expr.y.n._value * expr.x.type.get_size()

	if expr.op == idaapi.cot_ptr:
		return get_lvar_offset(expr.x)

	if expr.op == idaapi.cot_memptr and expr.x.op == idaapi.cot_var:
		return expr.x.v.idx, expr.m

	return -1, None

def get_lvar_struct_write(expr:idaapi.cexpr_t) -> tuple[int,int]:
	if expr.op != idaapi.cot_memref:
		return -1, None

	offset = 0
	while expr.op == idaapi.cot_memref:
		offset += expr.m
		expr = expr.x
	if expr.op == idaapi.cot_var:
		return expr.v.idx, offset
	return -1, None

# trying to get various forms of "var + X", where X is int
# not found is (-1, -1)
@_strip_casts
def get_lvar_offset(expr:idaapi.cexpr_t) -> tuple[int, int]:
	if expr.op == idaapi.cot_var:
		return expr.v.idx, 0

	# form ((CASTTYPE*)var) + N
	elif expr.op in [idaapi.cot_add, idaapi.cot_sub]:
		if expr.y.op != idaapi.cot_num:
			return -1, -1
		offset = expr.y.n._value
		if expr.op == idaapi.cot_sub:
			offset = - offset

		op_x = expr.x
		if op_x.op == idaapi.cot_var:
			var = op_x.v

		elif op_x.op == idaapi.cot_cast and op_x.x.op == idaapi.cot_var:
			var = op_x.x.v

		else:
			return -1, -1

		if op_x.type.is_ptr():
			sz = op_x.type.get_pointed_object().get_size()
			if sz == idaapi.BADSIZE: 
				raise BaseException("Failed to get object's size")
			offset = offset * sz

		return var.idx, offset

	else:
		return -1, -1

@_strip_casts
def get_gvar_offset(expr:idaapi.cexpr_t) -> tuple[int,int]:
	if expr.op == idaapi.cot_obj:
		return expr.obj_ea, 0

	# form ((CASTTYPE*)var) + N
	elif expr.op in [idaapi.cot_add, idaapi.cot_sub]:
		if expr.y.op != idaapi.cot_num:
			return -1, None
		offset = expr.y.n._value
		if expr.op == idaapi.cot_sub:
			offset = - offset

		op_x = expr.x
		if op_x.op == idaapi.cot_obj:
			obj_ea = op_x.obj_ea

		elif op_x.op == idaapi.cot_cast and op_x.x.op == idaapi.cot_obj:
			obj_ea = op_x.x.obj_ea

		else:
			return -1, None

		if op_x.type.is_ptr():
			sz = op_x.type.get_pointed_object().get_size()
			if sz == idaapi.BADSIZE: 
				raise BaseException("Failed to get object's size")
			offset = offset * sz

		return obj_ea, offset

	else:
		return -1, None

@_strip_casts
def get_int(expr:idaapi.cexpr_t) -> int|None:
	if expr.op == idaapi.cot_ref and expr.x.op == idaapi.cot_obj:
		return expr.x.obj_ea

	if expr.op == idaapi.cot_obj:
		return expr.obj_ea

	if expr.op == idaapi.cot_num:
		return expr.n._value

	return None