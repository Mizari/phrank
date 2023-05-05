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

def get_int(expr:idaapi.cexpr_t) -> int|None:
	expr = strip_casts(expr)
	if expr.op == idaapi.cot_ref and expr.x.op == idaapi.cot_obj:
		return expr.x.obj_ea

	if expr.op == idaapi.cot_obj:
		return expr.obj_ea

	if expr.op == idaapi.cot_num:
		return expr.n._value

	return None

def get_tif_member_name(tif:idaapi.tinfo_t, offset:int) -> str:
	udt_member = idaapi.udt_member_t()
	udt_member.offset = offset * 8
	if tif.find_udt_member(udt_member, idaapi.STRMEM_OFFSET) == -1:
		return ""
	else:
		return udt_member.name

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
		return "UNKNOWN"