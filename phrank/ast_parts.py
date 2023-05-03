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

	def get_functions(self) -> set[int]:
		if self.is_local():
			functions = {self.func_ea}
		else:
			functions = utils.get_func_calls_to(self.obj_ea)
		return functions


class VarUse:
	VAR_ADD = 0
	VAR_PTR = 1
	VAR_HELPER = 2
	VAR_REF = 3

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
	def __init__(self, var:Var, *uses:VarUse):
		self.var = var
		self.uses = list(uses)

	def uses_str(self) -> str:
		return "->".join(str(u) for u in self.uses)

	def __len__(self) -> int:
		return len(self.uses)

	def is_var_chain(self):
		# TODO helpers are assigns too
		return len(self.uses) == 0

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
		return f"{str(self.var)},{self.uses_str()}"



class SExpr:
	TYPE_INT = 0
	TYPE_VAR_USE_CHAIN = 1
	TYPE_FUNCTION = 2
	TYPE_BOOL_OP = 3
	TYPE_EXPLICIT_CALL = 4
	TYPE_IMPLICIT_CALL = 5

	def is_int(self): return self.op == self.TYPE_INT
	def is_var_use_chain(self): return self.op == self.TYPE_VAR_USE_CHAIN
	def is_function(self): return self.op == self.TYPE_FUNCTION
	def is_bool_op(self): return self.op == self.TYPE_BOOL_OP
	def is_explicit_call(self): return self.op == self.TYPE_EXPLICIT_CALL
	def is_implicit_call(self): return self.op == self.TYPE_IMPLICIT_CALL

	def __init__(self, t:int, expr_ea:int) -> None:
		self.op = t
		self.expr_ea = expr_ea
		self.x = None

	@classmethod
	def create_var_use_chain(cls, expr_ea:int, vuc:VarUseChain):
		obj = cls(cls.TYPE_VAR_USE_CHAIN, expr_ea)
		obj.x = vuc
		return obj

	@classmethod
	def create_function(cls, expr_ea:int, call_ea:int):
		obj = cls(cls.TYPE_FUNCTION, expr_ea)
		obj.x = call_ea
		return obj

	@classmethod
	def create_explicit_function(cls, expr_ea:int, explicit:int):
		obj = cls(cls.TYPE_EXPLICIT_CALL, expr_ea)
		obj.x = explicit
		return obj

	@classmethod
	def create_bool_op(cls, expr_ea:int):
		obj = cls(cls.TYPE_BOOL_OP, expr_ea)
		return obj

	@classmethod
	def create_int(cls, expr_ea:int, value:int):
		obj = cls(cls.TYPE_INT, expr_ea)
		obj.x = value
		return obj

	@property
	def func_ea(self) -> int:
		rv = utils.get_func_start(self.expr_ea)
		if rv == idaapi.BADADDR: rv = -1
		return rv

	@property
	def var_use_chain(self) -> VarUseChain|None:
		if not isinstance(self.x, VarUseChain): return None
		return self.x # type:ignore

	@property
	def function(self) -> int:
		if not isinstance(self.x, int): return -1
		return self.x # type:ignore


UNKNOWN_SEXPR = SExpr(-1, -1)



class VarWrite:
	def __init__(self, target:SExpr, value:SExpr):
		self.target = target
		self.value = value

	def is_assign(self):
		if not self.target.var_use_chain: return False
		return self.target.var_use_chain.is_var_chain()


class CallCast:
	def __init__(self, arg:SExpr, arg_id:int, func_call:SExpr):
		self.arg = arg
		self.func_call = func_call
		self.arg_id = arg_id

	def is_var_arg(self):
		if not self.arg.var_use_chain: return False
		return self.arg.var_use_chain.is_var_chain()


class VarUses:
	def __init__(self):
		self.writes:list[VarWrite]   = []
		self.reads:list[SExpr]     = []
		self.casts:list[CallCast]    = []

	def __len__(self):
		return len(self.writes) + len(self.reads) + len(self.casts)