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

def get_var(expr:idaapi.cexpr_t, actx:ASTCtx) -> Var|None:
	expr = utils.strip_casts(expr)
	if expr.op == idaapi.cot_var:
		return Var(actx.addr, expr.v.idx)
	if expr.op == idaapi.cot_obj and not utils.is_func_start(expr.obj_ea):
		return Var(expr.obj_ea)
	return None

def extract_vars(expr:idaapi.cexpr_t, actx:ASTCtx) -> set[Var]:
	v = get_var(expr, actx)
	if v is not None:
		return {v}
	vars = set()
	if expr.x is not None:
		vars.update(extract_vars(expr.x, actx))
	if expr.y is not None:
		vars.update(extract_vars(expr.y, actx))
	if expr.z is not None:
		vars.update(extract_vars(expr.z, actx))
	if expr.op == idaapi.cot_call:
		for a in expr.a:
			vars.update(extract_vars(a, actx))
	vars_dict = {v.varid: v for v in vars}
	vars = set(vars_dict.values())
	return vars

def get_var_use_chain(expr:idaapi.cexpr_t, actx:ASTCtx) -> VarUseChain|None:
	var = get_var(expr, actx)
	if var is not None:
		return VarUseChain(var)

	expr = utils.strip_casts(expr)
	if expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_helper:
		vuc = get_var_use_chain(expr.a[0], actx)
		if vuc is None:
			print("unknown chain var use expression operand", expr.opname, utils.expr2str(expr))
			return None

		var, use_chain = vuc.var, vuc.uses

		helper2offset = {
			"HIBYTE": 1,
			"LOBYTE": 0,
			"HIWORD": 2,
			"LOWORD": 0,
		}
		offset = helper2offset.get(expr.x.helper)
		if offset is None:
			print("WARNING: unknown helper", expr.x.helper)
			return None
		if len(use_chain) != 0:
			print("WARNING: helper of non-variable expr", utils.expr2str(expr))

		var_use = VarUse(offset, VarUse.VAR_HELPER)
		use_chain.append(var_use)
		return VarUseChain(var, *use_chain)

	op2use_type = {
		idaapi.cot_ptr: VarUse.VAR_PTR,
		idaapi.cot_memptr: VarUse.VAR_PTR,
		idaapi.cot_memref: VarUse.VAR_ADD,
		idaapi.cot_ref: VarUse.VAR_ADD,
		idaapi.cot_idx: VarUse.VAR_PTR,
		idaapi.cot_add: VarUse.VAR_ADD,
		idaapi.cot_sub: VarUse.VAR_ADD,
	}
	use_type = op2use_type.get(expr.op)
	if use_type is None:
		print("unknown chain var use expression operand", expr.opname, utils.expr2str(expr))
		return None

	vuc = get_var_use_chain(expr.x, actx)
	if vuc is None:
		return None

	var, use_chain = vuc.var, vuc.uses

	if expr.op in [idaapi.cot_ptr, idaapi.cot_ref]:
		offset = 0

	elif expr.op in [idaapi.cot_memptr, idaapi.cot_memref]:
		offset = expr.m

	elif expr.op in [idaapi.cot_idx, idaapi.cot_add, idaapi.cot_sub]:
		offset = utils.get_int(expr.y)
		if offset is None:
			print("unknown expression add operand", utils.expr2str(expr.y))
			return None
		if expr.op == idaapi.cot_sub: offset = -offset
		if expr.x.type.is_ptr():
			pointed = expr.x.type.get_pointed_object()
			offset *= pointed.get_size()

	# this should not happen at all, since expr op is check when use_type gets got
	else:
		raise Exception("Wut")

	var_use = VarUse(offset, use_type)
	use_chain.append(var_use)
	return VarUseChain(var, *use_chain)


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
				print("WARNING:", "failed to get member tif", str(ptif), hex(offset))
				return utils.UNKNOWN_TYPE
			return utils.make_shifted_ptr(tif, mtif, offset)

		print("WARNING:", f"adding to tif {str(tif)} isnt implemented")
		return utils.UNKNOWN_TYPE

	def transform_ptr(self, tif:idaapi.tinfo_t|utils.ShiftedStruct):
		if isinstance(tif, utils.ShiftedStruct) or not tif.is_ptr():
			print("WARNING:", "using non-pointer type as pointer", str(tif))
			return utils.UNKNOWN_TYPE

		offset = self.offset
		if tif.is_shifted_ptr():
			tif, shift_offset = utils.get_shifted_base(tif)
			if tif is None:
				print("WARNING:", "couldnt get base of shifted pointer")
				return utils.UNKNOWN_TYPE
			offset += shift_offset

		ptif = tif.get_pointed_object()
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
		print("chain transform", self.uses_str())
		for i, use in enumerate(self.uses):
			print("transforming", i, str(tif), str(use))
			tif = use.do_transform(tif)
			if tif is utils.UNKNOWN_TYPE:
				print("WARNING:", f"failed to calculate next step on {i} of uses {self.uses_str()}")
				break

		print("chain transform result", str(tif), '\n')
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