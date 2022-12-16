import idaapi


class VarUse:
	LOCAL_VAR  = 0
	GLOBAL_VAR = 1

	def __init__(self, vartype, varid):
		self.vartype = vartype
		self.varid = varid


class VarRead(VarUse):
	def __init__(self, vartype, varid, offset):
		super().__init__(vartype, varid)
		self.offset = offset


class VarWrite(VarUse):
	# write types
	PTR_WRITE = 0
	STRUCT_WRITE = 1

	def __init__(self, vartype, varid, value, offset, write_type):
		super().__init__(vartype, varid)
		self.value : idaapi.cexpr_t = value
		self.value_type = None
		self.offset = offset
		self.write_type = write_type


class VarAssign(VarUse):
	def __init__(self, vartype, varid, value):
		super().__init__(vartype, varid)
		self.value : idaapi.cexpr_t = value


class FuncCall:
	def __init__(self, call_expr):
		self.call_expr : idaapi.cexpr_t = call_expr.x
		self.args = call_expr.a
		self.address : int = -1
		self.name : str = ""

		if self.call_expr.op == idaapi.cot_obj:
			self.address = self.call_expr.obj_ea
			self.name = idaapi.get_func_name(self.address)
		elif self.call_expr.op == idaapi.cot_helper:
			self.name = self.call_expr.helper


class ReturnWrapper:
	def __init__(self, insn) -> None:
		self.insn = insn