from __future__ import annotations

import idaapi

import phrank.util_aux as util_aux

ARRAY_FUNCS = {"qmemcpy", "memcpy", "strncpy", "memset", "memmove", "strncat", "strncmp"}
ARRAY_FUNCS.update(['_' + s for s in ARRAY_FUNCS])

WARRAY_FUNCS = {"wcsncat", "wcsncpy"}
WARRAY_FUNCS.update(['_' + s for s in WARRAY_FUNCS])

PRINTF_FUNCS = {"vsnprintf", "snprintf"}
PRINTF_FUNCS.update(['_' + s for s in PRINTF_FUNCS])

HELPER_FUNCS = {"LOWORD", "HIWORD", "LOBYTE"}


def strip_casts(func):
	def wrapper(expr):
		while expr.op == idaapi.cot_cast:
			expr = expr.x
		return func(expr)
	return wrapper

def get_var_write(expr):
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

@strip_casts
def get_var_access(expr):
	if expr.op == idaapi.cot_memptr and expr.x.op == idaapi.cot_var:
		return expr.x.v.idx, expr.m + expr.x.type.get_size()

	if expr.op == idaapi.cot_idx:
		if expr.x.op != idaapi.cot_var or expr.y.op != idaapi.cot_num:
			return -1, None

		return expr.x.v.idx, (expr.y.n._value + 1) * expr.x.type.get_size()

	if expr.op == idaapi.cot_ptr:
		return get_var_offset(expr.x)

	return -1, None

# not found is (-1, None) since there are no such local variables
# with negative id, and there CAN be negative offset
def get_varptr_write_offset(expr):
	if expr.op == idaapi.cot_idx:
		if expr.x.op != idaapi.cot_var or expr.y.op != idaapi.cot_num:
			return None

		return expr.x.v.idx, expr.y.n._value * expr.x.type.get_size()

	if expr.op == idaapi.cot_ptr:
		return get_var_offset(expr.x)

	if expr.op == idaapi.cot_memptr and expr.x.op == idaapi.cot_var:
		return expr.x.v.idx, expr.m

	return -1, None

# trying to get various forms of "var + X", where X is int
# not found is (-1, None) since there are no such local variables
# with negative id, and there CAN be negative offset
@strip_casts
def get_var_offset(expr):
	if expr.op == idaapi.cot_var:
		return expr.v.idx, 0

	# form ((CASTTYPE*)var) + N
	elif expr.op in [idaapi.cot_add, idaapi.cot_sub]:
		if expr.y.op != idaapi.cot_num:
			return -1, None
		offset = expr.y.n._value
		if expr.op == idaapi.cot_sub:
			offset = - offset

		op_x = expr.x
		if op_x.op == idaapi.cot_var:
			var = op_x.v

		elif op_x.op == idaapi.cot_cast and op_x.x.op == idaapi.cot_var:
			var = op_x.x.v

		else:
			return -1, None

		if op_x.type.is_ptr():
			sz = op_x.type.get_pointed_object().get_size()
			if sz == idaapi.BADSIZE: 
				raise BaseException("Failed to get object's size")
			offset = offset * sz

		return var.idx, offset

	else:
		return -1, None

@strip_casts
def get_int(expr):
	if expr.op == idaapi.cot_ref and expr.x.op == idaapi.cot_obj:
		return expr.x.obj_ea

	if expr.op == idaapi.cot_obj:
		return expr.obj_ea

	if expr.op == idaapi.cot_num:
		return expr.n._value

	return None


class Write:
	def __init__(self, val):
		self.val : idaapi.cexpr_t|None = val

	def is_int(self, val=None):
		intval = get_int(self.val)
		if intval is None:
			return False

		if val is None:
			return True

		return val == intval

	def get_write_size(self):
		sz = self.val.type.get_size()
		if sz == idaapi.BADSIZE:
			raise BaseException("Failed to get write size " + self.val.opname)
		return sz

	def check_val(self, val):
		if isinstance(val, int):
			return self.is_int(val)
		return self.val == val

class VarAccess:
	def __init__(self, varid, offset):
		self.varid = varid
		self.offset = offset

	def get_var_use(self, var_id):
		if self.varid != var_id:
			return 0
		else:
			return self.offset

class VarWrite(Write):
	def __init__(self, varid, val):
		super().__init__(val)
		self.varid = varid

	def check(self, val=None):
		if val is not None and not self.check_val(val):
			return False
		return True

class VarPtrWrite(Write):
	def __init__(self, varid, val, offset):
		super().__init__(val)
		self.varid = varid
		self.offset : int|None = offset

	def get_int(self):
		return get_int(self.val)
	
	def get_var_use(self, var_id):
		if self.varid != var_id:
			return 0
		return self.offset + self.get_write_size()

	def check(self, offset=None, val=None):
		if offset is not None and self.offset != offset:
			return False

		if val is not None and not self.check_val(val):
			return False
		return True

class FuncCall:
	def __init__(self, call_expr):
		self._call_expr : idaapi.cexpr_t = call_expr
		self._func_ea : int = idaapi.BADADDR
		self._func_name : str|None = None

		if call_expr.x.op == idaapi.cot_obj:
			self._func_ea = call_expr.x.obj_ea
			self._func_name = idaapi.get_func_name(self._func_ea)
		elif call_expr.x.op == idaapi.cot_helper:
			self._func_name = call_expr.x.helper

		self._this_args : dict[int, int] = {}

	def get_ea(self):
		if self._func_ea == idaapi.BADADDR:
			return None
		return self._func_ea

	def get_nargs(self):
		return len(self._call_expr.a)

	def get_args(self):
		return self._call_expr.a

	def get_name(self):
		return self._func_name

	def get_var_offset(self):
		for arg in self._call_expr.a:
			varid, offset = get_var_offset(arg)
			if varid == -1:
				continue

			return varid, offset
		return None

	def get_var_use_size(self, var_id):
		nargs = self.get_nargs()
		if nargs == 0:
			return 0

		arg0 = self._call_expr.a[0]
		varid, offset = get_var_offset(arg0)
		if varid == var_id:
			func_use_value = 0
			if self._func_name in ARRAY_FUNCS:
				arg2 = self._call_expr.a[2]
				if arg2.op == idaapi.cot_num:
					func_use_value = arg2.n._value
			elif self._func_name in WARRAY_FUNCS:
				arg2 = self._call_expr.a[2]
				if arg2.op == idaapi.cot_num:
					func_use_value = arg2.n._value * 2
			elif self._func_name in PRINTF_FUNCS:
				arg2 = self._call_expr.a[1]
				if arg2.op == idaapi.cot_num:
					func_use_value = arg2.n._value

			if func_use_value != 0:
				return offset + func_use_value

		# sanity check
		if self._func_ea == idaapi.BADADDR:
			return 0

		# cant look into imported funcs, assume that args are somehow used there
		if util_aux.is_func_import(self._func_ea):
			return 1

		if idaapi.get_func(self._func_ea) is None:
			return 0

		max_var_use = 0
		for arg_id in range(nargs):
			arg = self._call_expr.a[arg_id]
			varid, offset = get_var_offset(arg)
			if varid == -1:
				continue

			if varid != var_id:
				continue

			"""
			fav: ASTAnalysis = ASTAnalysis.create(addr=self._func_ea)
			var_use = fav.get_var_use_size(arg_id)
			max_var_use = max(max_var_use, var_use + offset)
			"""
		return max_var_use


class ReturnWrapper:
	def __init__(self, insn) -> None:
		self.insn = insn

