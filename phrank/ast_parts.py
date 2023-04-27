from __future__ import annotations

import idaapi
import phrank.utils as utils


class ASTCtx:
	def __init__(self, addr:int):
		self.addr = addr

	@classmethod
	def empty(cls):
		return cls(-1)

	@classmethod
	def from_cfunc(cls, cfunc:idaapi.cfunc_t):
		return cls(cfunc.entry_ea)


class Var:
	def __init__(self, *varid):
		self.varid : int|tuple[int,int] = 0
		if len(varid) == 1:  # global
			self.varid = varid[0]
		elif len(varid) == 2:
			self.varid = tuple(varid)
		else:
			raise ValueError("Invalid length of variable identifier")

	def __eq__(self, __value:Var) -> bool:
		return self.varid == __value.varid

	def __hash__(self) -> int:
		return hash(self.varid)

	@property
	def func_ea(self) -> int:
		assert self.is_local()
		return self.varid[0] # type:ignore

	@property
	def lvar_id(self) -> int:
		assert self.is_local()
		return self.varid[1] # type:ignore

	@property
	def obj_ea(self) -> int:
		assert self.is_global()
		return self.varid # type: ignore

	def is_lvar(self, func_ea:int, lvar_id:int):
		return self.is_local() and self.varid == (func_ea, lvar_id)

	def is_gvar(self, gvar_id:int):
		return self.is_global() and self.varid == gvar_id

	def is_local(self):
		return isinstance(self.varid, tuple)

	def is_global(self):
		return isinstance(self.varid, int)

	def __str__(self) -> str:
		if self.is_local():
			return "Lvar(" + idaapi.get_name(self.func_ea) + "," + str(self.lvar_id) + ")"
		else:
			return idaapi.get_name(self.varid)

	def get_functions(self) -> list[int]:
		if self.is_local():
			functions = [self.func_ea]
		else:
			functions = utils.get_func_calls_to(self.obj_ea)
		return functions


class FuncCall:
	def __init__(self, func_ea:int, call_expr:idaapi.cexpr_t):
		self.func_ea = func_ea
		self.call_expr = call_expr.x
		self.implicit_var_use_chain:VarUseChain|None = None
		self.args = call_expr.a

	@property
	def address(self) -> int:
		if self.call_expr.op == idaapi.cot_obj:
			return self.call_expr.obj_ea
		else:
			return -1

	@property
	def name(self) -> str:
		if self.call_expr.op == idaapi.cot_obj:
			rv = idaapi.get_func_name(self.address)
			if rv is None: rv = ""
			return rv
		elif self.call_expr.op == idaapi.cot_helper:
			return self.call_expr.helper
		else:
			return ""

	def is_explicit(self):
		return self.call_expr.op == idaapi.cot_obj

	def is_helper(self):
		return self.call_expr.op == idaapi.cot_helper

	def is_implicit(self):
		return not self.is_explicit() and not self.is_helper()


class VarUse:
	VAR_ADD = 0
	VAR_PTR = 1
	VAR_HELPER = 2

	def __init__(self, offset:int, use_type:int):
		self.offset = offset
		self.use_type = use_type

	def is_ptr(self):
		return self.use_type == self.VAR_PTR

	def do_transform(self, tif:idaapi.tinfo_t|utils.ShiftedStruct):
		if self.is_add(): return self.transform_add(tif)
		elif self.is_ptr(): return self.transform_ptr(tif)
		else:
			print("WARNING:", f"this use {str(self)} isnt implemented")
			return utils.UNKNOWN_TYPE

	def transform_add(self, tif:idaapi.tinfo_t|utils.ShiftedStruct):
		offset = self.offset
		if isinstance(tif, utils.ShiftedStruct):
			tif = tif.tif

		if tif.is_struct(): # type:ignore
			member = utils.get_tif_member(tif, offset)
			if member is None:
				print("WARNING:", "failed to get member tif", str(tif), hex(offset))
				return utils.UNKNOWN_TYPE

			return member

		if tif.is_ptr() and (ptif := tif.get_pointed_object()).is_struct(): # type:ignore
			member = utils.get_tif_member(ptif, offset)
			if member is None:
				print("WARNING:", "failed to get member", str(ptif), hex(offset))
				return utils.UNKNOWN_TYPE

			mtif = member.tif
			if mtif is utils.UNKNOWN_TYPE:
				mtif = utils.str2tif("void*")
				# print("WARNING:", "failed to get member tif", str(ptif), hex(offset))
				# return utils.UNKNOWN_TYPE
			return utils.make_shifted_ptr(tif, mtif, offset)

		print("WARNING:", f"adding to tif {str(tif)} isnt implemented")
		return utils.UNKNOWN_TYPE

	def transform_ptr(self, tif:idaapi.tinfo_t|utils.ShiftedStruct):
		if isinstance(tif, utils.ShiftedStruct):
			tif = tif.tif

		if not tif.is_ptr(): # type:ignore
			print("WARNING:", "using non-pointer type as pointer", str(tif))
			return utils.UNKNOWN_TYPE

		offset = self.offset
		if tif.is_shifted_ptr(): # type:ignore
			tif, shift_offset = utils.get_shifted_base(tif)
			if tif is None:
				print("WARNING:", "couldnt get base of shifted pointer")
				return utils.UNKNOWN_TYPE
			offset += shift_offset

		ptif = tif.get_pointed_object() # type:ignore
		if not ptif.is_struct():
			print("WARNING:", "access pointer of non-struct isnt implemented", str(tif))
			return utils.UNKNOWN_TYPE

		member = utils.get_tif_member(ptif, offset)
		if member is None:
			print("WARNING:", "failed to get member tif", str(ptif), hex(offset))
			return utils.UNKNOWN_TYPE

		return member

	def is_add(self):
		return self.use_type == self.VAR_ADD

	def __str__(self) -> str:
		use_type_str = {
			self.VAR_ADD: "ADD",
			self.VAR_PTR: "PTR",
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

	def transform_type(self, tif:idaapi.tinfo_t) -> idaapi.tinfo_t|utils.ShiftedStruct:
		for i, use in enumerate(self.uses):
			tif = use.do_transform(tif)
			if tif is utils.UNKNOWN_TYPE:
				print("WARNING:", f"failed to calculate next step on {i} of uses {self.uses_str()}")
				break

		return tif

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
	def __init__(self, func_ea:int, var:Var, *uses:VarUse):
		super().__init__(var, *uses)
		self.func_ea = func_ea


class VarWrite(VarUseChain):
	USE_STR = "WRITE"
	def __init__(self, func_ea:int, var:Var, value:idaapi.cexpr_t, *uses:VarUse):
		super().__init__(var, *uses)
		self.value = value
		self.func_ea = func_ea

	def is_assign(self):
		# TODO helpers are assigns too
		return len(self.uses) == 0


class CallCast(VarUseChain):
	USE_STR = "CAST"
	def __init__(self, func_ea:int, var:Var, arg_id:int, func_call:FuncCall, *uses:VarUse):
		super().__init__(var, *uses)
		self.func_ea = func_ea
		self.func_call = func_call
		self.arg_id = arg_id

	def is_var_arg(self):
		return len(self.uses) == 0


class ReturnWrapper(VarUseChain):
	USE_STR = "RETURN"
	def __init__(self, func_ea:int, var:Var, retval, *uses:VarUse) -> None:
		super().__init__(var, *uses)
		self.func_ea = func_ea
		self.retval = retval


class VarUses:
	def __init__(self):
		self.writes:list[VarWrite]   = []
		self.reads:list[VarRead]     = []
		self.casts:list[CallCast]    = []

	def __len__(self):
		return len(self.writes) + len(self.reads) + len(self.casts)