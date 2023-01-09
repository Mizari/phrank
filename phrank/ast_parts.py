import idaapi


class Var:
	LOCAL_VAR  = 0
	GLOBAL_VAR = 1

	def __init__(self, vartype:int, varid:int):
		self.vartype = vartype
		self.varid = varid

	def is_lvar(self, lvar_id):
		return self.is_local() and self.varid == lvar_id

	def is_gvar(self, gvar_id):
		return self.is_global() and self.varid == gvar_id

	def is_local(self):
		return self.vartype == self.LOCAL_VAR

	def is_global(self):
		return self.vartype == self.GLOBAL_VAR


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


class VarRead():
	def __init__(self, var:Var, offset:int):
		self.var = var
		self.offset = offset


class VarWrite():
	def __init__(self, var:Var, value:idaapi.cexpr_t, chain):
		self.var = var
		self.value = value
		self.value_type = None
		self.chain:list[VarUse] = chain

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
			return 0
		if len(self.chain) == 1:
			0/0
		if self.chain[0].is_add() and self.chain[1].is_ptr():
			return self.chain[0].offset
		0/0


class VarAssign():
	def __init__(self, var:Var, value:idaapi.cexpr_t):
		self.var = var
		self.value = value


class FuncCall:
	def __init__(self, call_expr:idaapi.cexpr_t):
		self.call_expr = call_expr.x
		self.args = call_expr.a
		self.address : int = -1
		self.name : str = ""

		if self.call_expr.op == idaapi.cot_obj:
			self.address = self.call_expr.obj_ea
			self.name = idaapi.get_func_name(self.address)
		elif self.call_expr.op == idaapi.cot_helper:
			self.name = self.call_expr.helper


class CallCast():
	VAR_CAST = 0  #  v ; v + N
	REF_CAST = 1  # &v ; &v.f ; &(v + N)
	PTR_CAST = 2  # *v ; v->f ; *(v + N)
	def __init__(self, var:Var, offset:int, cast_type:int, arg_id:int, func_call:FuncCall):
		self.var = var
		self.offset = offset
		self.cast_type = cast_type
		self.func_call = func_call
		self.arg_id = arg_id
		self.arg_type = None


class ReturnWrapper:
	def __init__(self, insn) -> None:
		self.insn = insn