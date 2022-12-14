from __future__ import annotations

import idaapi

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
		self.call_expr : idaapi.cexpr_t = call_expr.x
		self.args = call_expr.a
		self.address : int = -1
		self.name : str|None = None

		if call_expr.op == idaapi.cot_obj:
			self.address = call_expr.obj_ea
			self.name = idaapi.get_func_name(self.address)
		elif call_expr.op == idaapi.cot_helper:
			self.name = call_expr.helper


class ReturnWrapper:
	def __init__(self, insn) -> None:
		self.insn = insn