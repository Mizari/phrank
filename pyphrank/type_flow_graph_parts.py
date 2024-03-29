from __future__ import annotations
from typing import Any

import idaapi
import pyphrank.utils as utils


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
	def __init__(self, *varid:int) -> None:
		self.varid : int|tuple[int,...] = 0
		if len(varid) == 1:  # global
			self.varid = varid[0]
		elif len(varid) == 2:
			self.varid = tuple(varid)
		else:
			raise ValueError("Invalid length of variable identifier")

	def __eq__(self, __value:object) -> bool:
		if __value is None:
			return False
		if not isinstance(__value, Var):
			raise NotImplementedError(f"bad type {type(__value)}")
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

	def is_ptr(self): return self.use_type == self.VAR_PTR
	def is_add(self): return self.use_type == self.VAR_ADD
	def is_ref(self): return self.use_type == self.VAR_REF

	def __init__(self, offset:int, use_type:int):
		self.offset = offset
		self.use_type = use_type

	def do_transform(self, tif:idaapi.tinfo_t|utils.ShiftedStruct):
		if self.is_add():
			return self.transform_add(tif)
		elif self.is_ptr():
			return self.transform_ptr(tif)
		elif self.is_ref():
			return self.transform_ref(tif)
		else:
			utils.log_debug(f"this use {str(self)} isnt implemented")
			return utils.UNKNOWN_TYPE

	def transform_add(self, tif:idaapi.tinfo_t|utils.ShiftedStruct):
		offset = self.offset
		if isinstance(tif, utils.ShiftedStruct):
			tif = tif.tif
			if tif is utils.UNKNOWN_TYPE:
				utils.log_debug("failed to get member type for in add transformation")
				return utils.UNKNOWN_TYPE

		if tif.is_struct(): # type:ignore
			member = utils.get_tif_member(tif, offset)
			if member is None:
				utils.log_debug(f"failed to get member tif {str(tif)} {hex(offset)}")
				return utils.UNKNOWN_TYPE

			return member

		if tif.is_ptr() and (ptif := tif.get_pointed_object()).is_struct(): # type:ignore
			member = utils.get_tif_member(ptif, offset)
			if member is None:
				utils.log_debug(f"failed to get member {str(ptif)} {hex(offset)}")
				return utils.UNKNOWN_TYPE

			mtif = member.tif
			if mtif is utils.UNKNOWN_TYPE:
				mtif = utils.str2tif("void*")
			return utils.make_shifted_ptr(tif, mtif, offset)

		utils.log_debug(f"adding to tif {str(tif)} isnt implemented")
		return utils.UNKNOWN_TYPE

	def transform_ptr(self, tif:idaapi.tinfo_t|utils.ShiftedStruct):
		if isinstance(tif, utils.ShiftedStruct):
			tif = tif.tif
			if tif is utils.UNKNOWN_TYPE:
				utils.log_debug("failed to get member type for ptr transformation")
				return utils.UNKNOWN_TYPE

		if not tif.is_ptr(): # type:ignore
			utils.log_debug(f"using non-pointer type as pointer {str(tif)}")
			return utils.UNKNOWN_TYPE

		offset = self.offset
		if tif.is_shifted_ptr(): # type:ignore
			tif, shift_offset = utils.get_shifted_base(tif)
			if tif is None:
				utils.log_debug("couldnt get base of shifted pointer")
				return utils.UNKNOWN_TYPE
			offset += shift_offset

		ptif = tif.get_pointed_object() # type:ignore
		if not ptif.is_struct():
			utils.log_debug(f"access pointer of non-struct isnt implemented {str(tif)}")
			return utils.UNKNOWN_TYPE

		member = utils.get_tif_member(ptif, offset)
		if member is None:
			utils.log_debug(f"failed to get member tif {str(ptif)} {hex(offset)}")
			return utils.UNKNOWN_TYPE

		return member

	def transform_ref(self, tif:idaapi.tinfo_t|utils.ShiftedStruct):
		if self.offset != 0:
			utils.log_debug("non-zero ref isnt implemented yet")
			return utils.UNKNOWN_TYPE

		if isinstance(tif, idaapi.tinfo_t):
			ptif = idaapi.tinfo_t()
			ptif.create_ptr(tif)
			return ptif
		else:
			utils.log_debug("shifted member reference isnt implemented yet")
			return utils.UNKNOWN_TYPE

	def __str__(self) -> str:
		use_type_str = {
			self.VAR_ADD: "Add",
			self.VAR_PTR: "Ptr",
			self.VAR_HELPER: "Hlp",
			self.VAR_REF: "Ref",
		}.get(self.use_type)
		if use_type_str is None:
			raise RuntimeError("Object is initialized incorrectly")
		return f"{use_type_str}({str(self.offset)})"


class VarUseChain:
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
				utils.log_debug(f"failed to calculate next step on {i} of uses {self.uses_str()}")
				break

		return tif

	def is_possible_ptr(self) -> bool:
		return self.get_ptr_offset() is not None

	def get_ptr_offset(self) -> int|None:
		if len(self.uses) == 0:
			return 0

		use0 = self.uses[0]
		if len(self.uses) >= 1 and (use0.is_ptr() or use0.is_add()):
			return use0.offset

		if len(self.uses) >= 2 and self.uses[0].is_add() and self.uses[1].is_ptr():
			return self.uses[0].offset
		return None

	def __str__(self) -> str:
		if len(self.uses) == 0:
			return str(self.var)
		return f"{str(self.var)},{self.uses_str()}"


class SExpr:
	TYPE_LITERAL = 0
	TYPE_VAR_USE_CHAIN = 1
	TYPE_FUNCTION = 2
	TYPE_BOOL_OP = 3
	TYPE_CALL = 4
	TYPE_ASSIGN = 5
	TYPE_BINARY_OP = 6
	TYPE_RW_OP = 7
	TYPE_REF = 8
	TYPE_PTR = 9
	TYPE_TERN = 10
	TYPE_PARTIAL = 11
	TYPE_COMBINE = 12

	def is_type_literal(self): return self.op == self.TYPE_LITERAL
	def is_var_use_chain(self): return self.op == self.TYPE_VAR_USE_CHAIN
	def is_function(self): return self.op == self.TYPE_FUNCTION
	def is_bool_op(self): return self.op == self.TYPE_BOOL_OP
	def is_binary_op(self): return self.op == self.TYPE_BINARY_OP
	def is_call(self): return self.op == self.TYPE_CALL
	def is_assign(self): return self.op == self.TYPE_ASSIGN
	def is_rw_op(self): return self.op == self.TYPE_RW_OP
	def is_ref(self): return self.op == self.TYPE_REF
	def is_ptr(self): return self.op == self.TYPE_PTR
	def is_tern(self): return self.op == self.TYPE_TERN
	def is_partial(self): return self.op == self.TYPE_PARTIAL
	def is_combine(self): return self.op == self.TYPE_COMBINE

	def is_var_use(self, var:Var|None=None) -> bool:
		if self.var_use_chain is None:
			return False
		vuc = self.var_use_chain
		if var is not None:
			return vuc.var == var
		return True

	def is_var(self, var:Var|None=None) -> bool:
		if self.var_use_chain is None:
			return False
		vuc = self.var_use_chain
		if len(vuc) != 0:
			return False
		if var is not None:
			return vuc.var == var
		return True

	def is_var_write(self, var:Var|None=None) -> bool:
		"""
		e.g: some_uses(var) = anything
		"""
		if not self.is_assign():
			return False
		if (vuc := self.target.var_use_chain) is None:
			return False
		if vuc.var != var:
			return False
		return len(vuc.uses) != 0

	def is_move_to_var(self, var:Var|None=None) -> bool:
		"""
		e.g.: var = anything
		"""
		if not self.is_assign():
			return False
		if (vuc := self.target.var_use_chain) is None:
			return False
		if vuc.var != var:
			return False
		return len(vuc.uses) == 0

	def is_move_from_var(self, var:Var|None=None) -> bool:
		"""
		e.g: anything = var
		"""
		if not self.is_assign():
			return False
		return self.value.is_var(var)

	def is_explicit_call(self):
		if self.op != self.TYPE_CALL:
			return False
		return self.function.is_function()

	def is_implicit_call(self):
		if self.op != self.TYPE_CALL:
			return False
		return not self.function.is_function()

	def __init__(self, t:int, addr=-1) -> None:
		self.op = t
		if addr == idaapi.BADADDR:
			addr = -1
		self.addr = addr
		self._x:Any = None
		self._y:Any = None

	def __str__(self) -> str:
		if self.is_type_literal():
			return f"TypeLiteral[{self.literal_tinfo}]"
		elif self.is_var_use_chain():
			if self.is_var():
				return f"{self.var_use_chain}"
			return f"VarUseChain[{self.var_use_chain}]"
		elif self.is_function():
			return f"Func[{idaapi.get_name(self.func_addr)}]"
		elif self.is_bool_op():
			return f"BoolOp[{self.x}&&{self.y}]"
		elif self.is_call():
			return f"Call[{self.function}]"
		elif self.is_assign():
			return f"{self.x} = {self.y}"
		elif self.is_binary_op():
			return f"BinOp[{self.x},{self.y}]"
		else:
			return ""

	def extract_var_use_chains(self) -> set[VarUseChain]:
		rv = set()
		if isinstance(self._x, VarUseChain):
			rv.add(self._x)
		elif isinstance(self._x, SExpr):
			rv.update(self._x.extract_var_use_chains())
		if isinstance(self._y, SExpr):
			rv.update(self._y.extract_var_use_chains())
		return rv

	def extract_vars(self) -> set[Var]:
		return {vuc.var for vuc in self.extract_var_use_chains()}

	@classmethod
	def create_var_use_chain(cls, vuc:VarUseChain, addr=-1):
		obj = cls(cls.TYPE_VAR_USE_CHAIN, addr=addr)
		obj._x = vuc
		return obj

	@classmethod
	def create_function(cls, call_ea:int, addr=-1):
		obj = cls(cls.TYPE_FUNCTION, addr=addr)
		obj._x = call_ea
		return obj

	@classmethod
	def create_call(cls, function:SExpr, addr=-1):
		obj = cls(cls.TYPE_CALL, addr=addr)
		obj._x = function
		return obj

	@classmethod
	def create_bool_op(cls, x:SExpr, y:SExpr, addr=-1):
		obj = cls(cls.TYPE_BOOL_OP, addr=addr)
		obj._x = x
		obj._y = y
		return obj

	@classmethod
	def create_binary_op(cls, x:SExpr, y:SExpr, addr=-1):
		obj = cls(cls.TYPE_BINARY_OP, addr=addr)
		obj._x = x
		obj._y = y
		return obj

	@classmethod
	def create_type_literal(cls, literal_type:idaapi.tinfo_t, addr=-1):
		obj = cls(cls.TYPE_LITERAL, addr=addr)
		obj._x = literal_type
		return obj

	@classmethod
	def create_assign(cls, target:SExpr, value:SExpr, addr=-1):
		obj = cls(cls.TYPE_ASSIGN, addr=addr)
		obj._x = target
		obj._y = value
		return obj

	@classmethod
	def create_rw_op(cls, target:SExpr, value:SExpr, addr=-1):
		obj = cls(cls.TYPE_RW_OP, addr=addr)
		obj._x = target
		obj._y = value
		return obj

	@classmethod
	def create_ref(cls, base:SExpr, addr=-1):
		obj = cls(cls.TYPE_REF, addr=addr)
		obj._x = base
		return obj

	@classmethod
	def create_ptr(cls, base:SExpr, offset=0, addr=-1):
		obj = cls(cls.TYPE_PTR, addr=addr)
		obj._x = base
		obj._y = offset
		return obj

	@classmethod
	def create_tern(cls, x:SExpr, y:SExpr, addr=-1):
		obj = cls(cls.TYPE_TERN, addr=addr)
		obj._x = x
		obj._y = y
		return obj

	@classmethod
	def create_partial(cls, base:SExpr, offset:int, size:int, addr=-1):
		obj = cls(cls.TYPE_PARTIAL, addr=addr)
		obj._x = base
		obj._y = (offset, size)
		return obj

	@classmethod
	def create_combine(cls, x:SExpr, y:SExpr, addr=-1):
		obj = cls(cls.TYPE_COMBINE, addr=addr)
		obj._x = x
		obj._y = y
		return obj

	@property
	def func_ea(self) -> int:
		rv = utils.get_func_start(self.addr)
		if rv == idaapi.BADADDR:
			rv = -1
		return rv

	@property
	def var_use_chain(self) -> VarUseChain|None:
		if not isinstance(self._x, VarUseChain):
			return None
		return self._x # type:ignore

	@property
	def var(self) -> Var|None:
		if self.var_use_chain is None:
			return None
		if len(self.var_use_chain) != 0:
			return None
		return self.var_use_chain.var

	@property
	def func_addr(self) -> int:
		return self._x

	@property
	def function(self) -> SExpr:
		return self._x

	@property
	def target(self) -> SExpr:
		return self._x

	@property
	def value(self) -> SExpr:
		return self._y

	@property
	def x(self) -> SExpr:
		return self._x

	@property
	def y(self) -> SExpr:
		return self._y

	@property
	def literal_tinfo(self) -> idaapi.tinfo_t:
		return self._x

	@property
	def base(self) -> SExpr:
		return self._x

	@property
	def offset(self) -> int:
		return self._y


UNKNOWN_SEXPR = SExpr(-1, -1)


class Node:
	RETURN = 0
	EXPR = 1
	CALL_CAST = 2
	TYPE_CAST = 3
	def __init__(self, node_type, sexpr:SExpr, y=None, z=None) -> None:
		self.node_type = node_type
		self.sexpr = sexpr
		self.y = y
		self.z = z
		self.children : set[Node] = set()
		self.parents : set[Node] = set()

	def remove_node(self):
		for parent in self.parents:
			parent.children.remove(self)
		for child in self.children:
			child.parents.remove(self)
		for parent in self.parents:
			for child in self.children:
				parent.children.add(child)
				child.parents.add(parent)

	def is_leaf(self):
		return len(self.children) == 0

	def copy(self) -> Node:
		""" Copy node without edges """
		return Node(self.node_type, self.sexpr, self.y, self.z)

	def iterate_children(self):
		visited_nodes = set()
		queue = list(self.children)
		while len(queue) != 0:
			node = queue.pop(0)
			if node in visited_nodes:
				continue
			visited_nodes.add(node)
			yield node

			queue += list(node.children)

	def __str__(self) -> str:
		if self.node_type == self.EXPR and self.sexpr is UNKNOWN_SEXPR:
			return "NopNode"

		node_type = {
			self.RETURN: "Return",
			self.EXPR: "Expr",
			self.CALL_CAST: "CallCast",
			self.TYPE_CAST: "TypeCast",
		}.get(self.node_type, "UnknownNode")
		sexpr_text = str(self.sexpr)
		if self.is_call_cast():
			sexpr_text += f" -> [{self.func_call},{self.arg_id}]"
		elif self.is_type_cast():
			sexpr_text += f" -> {self.tif}"

		diff = (len(sexpr_text) - len(node_type)) // 2 - 1
		if diff > 0:
			node_type = diff * ' ' + node_type
		rv = f"{node_type}Node\n{sexpr_text}"
		return rv

	def max_depth(self):
		m = 1
		for n in self.children:
			m = max(m, n.max_depth() + 1)
		return m

	def print_node(self, lvl):
		print(f"{lvl * ' '}node {str(self)} children_len={len(self.children)}")
		for c in self.children:
			c.print_node(lvl + 1)

	def is_return(self):
		return self.node_type == self.RETURN

	def is_expr(self):
		return self.node_type == self.EXPR

	def is_call_cast(self):
		return self.node_type == self.CALL_CAST

	def is_type_cast(self):
		return self.node_type == self.TYPE_CAST

	@property
	def arg_id(self) -> int:
		return self.y # type: ignore

	@property
	def func_call(self) -> SExpr:
		return self.z # type: ignore

	@property
	def tif(self) -> idaapi.tinfo_t:
		return self.y


NOP_NODE = Node(Node.EXPR, UNKNOWN_SEXPR)