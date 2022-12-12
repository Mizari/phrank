from __future__ import annotations

import idaapi
import phrank.utils as utils

class Write:
	def __init__(self, val):
		self.val : idaapi.cexpr_t|None = val

	def is_int(self, val=None):
		intval = utils.get_int(self.val)
		if intval is None:
			return False

		if val is None:
			return True

		return val == intval

	def check_val(self, val):
		if isinstance(val, int):
			return self.is_int(val)
		return self.val == val

class LvarRead:
	def __init__(self, varid, offset):
		self.varid = varid
		self.offset = offset

	def get_var_use(self, var_id):
		if self.varid != var_id:
			return 0
		else:
			return self.offset

class LvarAssign(Write):
	def __init__(self, varid, val):
		super().__init__(val)
		self.varid = varid

	def check(self, val=None):
		if val is not None and not self.check_val(val):
			return False
		return True

class GvarAssign(Write):
	def __init__(self, varid, val):
		super().__init__(val)
		self.varid = varid

class GvarWrite(Write):
	def __init__(self, varid, val, offset):
		super().__init__(val)
		self.varid = varid
		self.val = val
		self.offset = offset

class GvarRead:
	def __init__(self) -> None:
		pass

class LvarWrite(Write):
	def __init__(self, varid, val, offset):
		super().__init__(val)
		self.varid = varid
		self.offset : int|None = offset

	def get_int(self):
		return utils.get_int(self.val)

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
			varid, offset = utils.get_var_offset(arg)
			if varid == -1:
				continue

			return varid, offset
		return None

	def get_var_use_size(self, var_id):
		nargs = self.get_nargs()
		if nargs == 0:
			return 0

		arg0 = self._call_expr.a[0]
		varid, offset = utils.get_var_offset(arg0)
		if varid == var_id:
			func_use_value = 0
			if self._func_name in utils.ARRAY_FUNCS:
				arg2 = self._call_expr.a[2]
				if arg2.op == idaapi.cot_num:
					func_use_value = arg2.n._value
			elif self._func_name in utils.WARRAY_FUNCS:
				arg2 = self._call_expr.a[2]
				if arg2.op == idaapi.cot_num:
					func_use_value = arg2.n._value * 2
			elif self._func_name in utils.PRINTF_FUNCS:
				arg2 = self._call_expr.a[1]
				if arg2.op == idaapi.cot_num:
					func_use_value = arg2.n._value

			if func_use_value != 0:
				return offset + func_use_value

		# sanity check
		if self._func_ea == idaapi.BADADDR:
			return 0

		# cant look into imported funcs, assume that args are somehow used there
		if utils.is_func_import(self._func_ea):
			return 1
		return 0


class ReturnWrapper:
	def __init__(self, insn) -> None:
		self.insn = insn

