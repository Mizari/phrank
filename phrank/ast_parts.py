from __future__ import annotations

import idaapi


class ASTCtx:
	def __init__(self, addr):
		self.addr = addr

	@classmethod
	def empty(cls):
		return cls(-1)

	@classmethod
	def from_cfunc(cls, cfunc:idaapi.cfunc_t):
		return cls(cfunc.entry_ea)


class Var:
	def __init__(self, *varid):
		if len(varid) == 1:  # global
			self.varid = varid[0]
		elif len(varid) == 2:
			self.varid = tuple(varid)
		else:
			raise ValueError("Invalid length of variable identifier")

	def is_lvar(self, func_ea, lvar_id):
		return self.is_local() and self.varid == (func_ea, lvar_id)

	def is_gvar(self, gvar_id):
		return self.is_global() and self.varid == gvar_id

	def is_local(self):
		return isinstance(self.varid, tuple)

	def is_global(self):
		return isinstance(self.varid, int)

	def __str__(self) -> str:
		if self.is_local():
			return "Lvar(" + idaapi.get_name(self.varid[0]) + "," + str(self.varid[1]) + ")"
		else:
			return idaapi.get_name(self.varid)


class VarUse:
	VAR_ADD = 0
	VAR_PTR = 1
	VAR_REF = 2

	def __init__(self, var: Var, offset:int, use_type:int):
		self.var = var
		self.offset = offset
		self.use_type = use_type

	def is_ptr(self):
		return self.use_type == self.VAR_PTR

	def is_ref(self):
		return self.use_type == self.VAR_REF

	def is_add(self):
		return self.use_type == self.VAR_ADD

	def __str__(self) -> str:
		use_type_str = {
			self.VAR_ADD: "ADD",
			self.VAR_PTR: "PTR",
			self.VAR_REF: "REF",
		}.get(self.use_type)
		return use_type_str + "Use(" + str(self.var) + "," + str(self.offset) + ")"


class VarRead():
	def __init__(self, var:Var, chain:list[VarUse]):
		self.var = var
		self.chain = chain


class VarWrite():
	def __init__(self, var:Var, value:idaapi.cexpr_t, chain:list[VarUse]):
		self.var = var
		self.value = value
		self.value_type = None
		self.chain = chain

	def is_ptr_write(self):
		if len(self.chain) > 0 and self.chain[0].is_ptr():
			return True
		if len(self.chain) > 1 and self.chain[0].is_add() and self.chain[1].is_ptr():
			return True
		return False

	def get_ptr_write_offset(self):
		if len(self.chain) == 0:
			0/0
		if self.chain[0].is_ptr():
			return self.chain[0].offset
		if len(self.chain) == 1:
			0/0
		if self.chain[0].is_add() and self.chain[1].is_ptr():
			return self.chain[0].offset
		0/0


class VarAssign():
	def __init__(self, var:Var, value:idaapi.cexpr_t):
		self.var = var
		self.value = value
		self.value_type = None


class FuncCall:
	def __init__(self, call_expr:idaapi.cexpr_t):
		self.call_expr = call_expr.x
		self.implicit_var_use_chain = None
		self.args = call_expr.a
		self.address : int = -1
		self.name : str = ""

		if self.call_expr.op == idaapi.cot_obj:
			self.address = self.call_expr.obj_ea
			self.name = idaapi.get_func_name(self.address)
		elif self.call_expr.op == idaapi.cot_helper:
			self.name = self.call_expr.helper

	def is_explicit(self):
		return self.call_expr.op == idaapi.cot_obj

	def is_helper(self):
		return self.call_expr.op == idaapi.cot_helper

	def is_implicit(self):
		return not self.is_explicit() and not self.is_helper()


class CallCast():
	def __init__(self, var:Var, chain:list[VarUse], arg_id:int, func_call:FuncCall):
		self.var = var
		self.chain = chain
		self.func_call = func_call
		self.arg_id = arg_id
		self.arg_type = None

	def is_var_arg(self):
		return len(self.chain) == 0

	def get_ptr_chain_offset(self):
		if len(self.chain) == 0:
			return 0
		if len(self.chain) == 1 and self.chain[0].is_add():
			return self.chain[0].offset
		return None


class ReturnWrapper:
	def __init__(self, retval, var:Var, chain:list[VarUse]) -> None:
		self.retval = retval
		self.var = var
		self.chain = chain