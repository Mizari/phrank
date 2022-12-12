from __future__ import annotations

import idaapi
import phrank.utils as utils

class Write:
	def __init__(self, val):
		self.val : idaapi.cexpr_t|None = val

class LvarRead:
	def __init__(self, varid, offset):
		self.varid = varid
		self.offset = offset

class LvarAssign(Write):
	def __init__(self, varid, val):
		super().__init__(val)
		self.varid = varid

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


class ReturnWrapper:
	def __init__(self, insn) -> None:
		self.insn = insn

