from __future__ import annotations

import idaapi
import phrank.utils as utils


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


class FuncCall:
	def __init__(self, call_expr:idaapi.cexpr_t):
		self.call_expr = call_expr.x
		self.implicit_var_use_chain:VarUseChain|None = None
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


class VarUse:
	VAR_ADD = 0
	VAR_PTR = 1
	VAR_REF = 2
	VAR_HELPER = 3

	def __init__(self, offset:int, use_type:int):
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
			self.VAR_HELPER: "HLP",
		}.get(self.use_type)
		if use_type_str is None:
			raise RuntimeError("Object is initialized incorrectly")
		return f"{use_type_str}Use({str(self.offset)})"


class VarUseChain:
	USE_STR = ""
	def __init__(self, var:Var, *uses:VarUse):
		self.var = var
		self.uses = list(uses)

	def uses_str(self) -> str:
		return "->".join(str(u) for u in self.uses)

	def __len__(self) -> int:
		return len(self.uses)

	def get_final_tif(self, tif:idaapi.tinfo_t) -> idaapi.tinfo_t|idaapi.udt_member_t|None:
		if len(self.uses) == 0:
			return tif

		for i, use in enumerate(self.uses):
			offset = use.offset
			if use.is_add():
				if tif.is_struct() and i == len(self.uses) - 1:
					return utils.get_tif_member(tif, offset)

				elif tif.is_ptr():
					ptif = tif.get_pointed_object()
					mtif = utils.get_tif_member_type(ptif, offset)
					if mtif is utils.UNKNOWN_TYPE:
						print("WARNING:", "failed to get member tif", str(ptif), hex(offset))
						return None
					tif = utils.make_shifted_ptr(tif, mtif, offset)

				else:
					return None

			elif use.is_ptr():
				if not tif.is_ptr():
					print("WARNING:", "using non-pointer type as pointer", str(tif))
					return None

				if tif.is_shifted_ptr():
					tif, shift_offset = utils.get_shifted_base(tif)
					if tif is None:
						print("WARNING:", "couldnt get base of shifted pointer")
						return None
					offset += shift_offset

				ptif = tif.get_pointed_object()
				if ptif.is_struct() and i == len(self.uses) - 1:
					return utils.get_tif_member(ptif, offset)

				mtif = utils.get_tif_member_type(ptif, offset)
				if mtif is utils.UNKNOWN_TYPE:
					print("WARNING:", "unknown struct member", str(ptif), hex(offset))
					return None

				tif = mtif

			else:
				return None

	def is_possible_ptr(self) -> bool:
		return self.get_ptr_offset() is not None

	def get_ptr_offset(self) -> int|None:
		if len(self.uses) == 0:
			return 0

		use0 = self.uses[0]
		if len(self.uses) == 1 and (use0.is_ptr() or use0.is_add()):
			return use0.offset

		if len(self.uses) == 2 and self.uses[0].is_add() and self.uses[1].is_ptr():
			return self.uses[0].offset
		return None

	def __str__(self) -> str:
		return f"{self.USE_STR}({str(self.var)},{self.uses_str()})"


class VarRead(VarUseChain):
	USE_STR = "READ"
	def __init__(self, var:Var, *uses:VarUse):
		super().__init__(var, *uses)


class VarWrite(VarUseChain):
	USE_STR = "WRITE"
	def __init__(self, var:Var, value:idaapi.cexpr_t, *uses:VarUse):
		super().__init__(var, *uses)
		self.value = value
		self.value_type = utils.UNKNOWN_TYPE

	def is_assign(self):
		# TODO helpers are assigns too
		return len(self.uses) == 0


class CallCast(VarUseChain):
	USE_STR = "CAST"
	def __init__(self, var:Var, arg_id:int, func_call:FuncCall, *uses:VarUse):
		super().__init__(var, *uses)
		self.func_call = func_call
		self.arg_id = arg_id
		self.arg_type = utils.UNKNOWN_TYPE

	def is_var_arg(self):
		return len(self.uses) == 0


class ReturnWrapper(VarUseChain):
	USE_STR = "RETURN"
	def __init__(self, var:Var, retval, *uses:VarUse) -> None:
		super().__init__(var, *uses)
		self.retval = retval


class VarUses:
	def __init__(self):
		self.writes:list[VarWrite]   = []
		self.reads:list[VarRead]     = []
		self.casts:list[CallCast]    = []

	def __len__(self):
		return len(self.writes) + len(self.reads) + len(self.casts)