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


class VarRead():
	def __init__(self, var:Var, offset:int):
		self.var = var
		self.offset = offset


class VarWrite():
	# write types
	PTR_WRITE = 0
	STRUCT_WRITE = 1

	def __init__(self, var:Var, value:idaapi.cexpr_t, offset:int, write_type:int):
		self.var = var
		self.value = value
		self.value_type = None
		self.offset = offset
		self.write_type = write_type


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