from __future__ import annotations

import idaapi

import pyphrank.utils as utils
import pyphrank.settings as settings
from pyphrank.type_flow_graph_parts import SExpr, ASTCtx, Node, NOP_NODE
from pyphrank.type_flow_graph_parts import Var, VarUse, VarUseChain, UNKNOWN_SEXPR
from pyphrank.type_flow_graph import TFG


bool_operations = {
	idaapi.cot_uge, idaapi.cot_sge,
	idaapi.cot_sgt, idaapi.cot_eq, idaapi.cot_ne, idaapi.cot_slt,
	idaapi.cot_land, idaapi.cot_sle, idaapi.cot_ult,
	idaapi.cot_ule, idaapi.cot_lor, idaapi.cot_ugt,
}

binary_operations = {
	idaapi.cot_mul, idaapi.cot_sub, idaapi.cot_bor, idaapi.cot_band,
	idaapi.cot_sshr, idaapi.cot_ushr, idaapi.cot_shl, idaapi.cot_add,
	idaapi.cot_sdiv, idaapi.cot_udiv, idaapi.cot_smod, idaapi.cot_umod,
	idaapi.cot_xor,
}

int_rw_operations = {
	idaapi.cot_postdec, idaapi.cot_predec, idaapi.cot_preinc,
	idaapi.cot_postinc,
}

value_rw_operations = {
	idaapi.cot_asgadd, idaapi.cot_asgband, idaapi.cot_asgbor,
	idaapi.cot_asgmul, idaapi.cot_asgsdiv, idaapi.cot_asgshl,
	idaapi.cot_asgsmod, idaapi.cot_asgsshr, idaapi.cot_asgsub,
	idaapi.cot_asgudiv, idaapi.cot_asgumod, idaapi.cot_asgushr,
	idaapi.cot_asgxor,
}

# https://hex-rays.com/blog/igors-tip-of-the-week-67-decompiler-helpers/
helper2offset = {
	"LOBYTE": 0,
	"LOWORD": 0,
	"LODWORD": 0,
	"HIBYTE": 4,
	"HIWORD": 2,
	"HIDWORD": 4,
}

helper2size = {
	"LOBYTE": 1,
	"LOWORD": 2,
	"LODWORD": 4,
	"HIBYTE": 1,
	"HIWORD": 2,
	"HIDWORD": 4,
}

for i in range(4, 16, 4):
	s = "DWORD" + str(i//4)
	helper2offset[s] = i
	helper2size[s] = 4

for i in range(2, 16, 2):
	s = "WORD" + str(i//2)
	helper2offset[s] = i
	helper2size[s] = 2

for i in range(1,15):
	s = "BYTE" + str(i)
	helper2offset[s] = i
	helper2size[s] = 1

helper2offset.update({'S'+k:v for k,v in helper2offset.items()})
helper2size.update({'S'+k:v for k,v in helper2size.items()})


combine_helpers = {
	"__PAIR16__",
	"__SPAIR16__",
	"__PAIR32__",
	"__SPAIR32__",
	"__PAIR64__",
	"__SPAIR64__",
	"__PAIR128__",
	"__SPAIR128__",
}

known_helpers = {
	"_enable", "_disable",
	"__outbyte", "__inbyte",
	"__outword", "__inword",
	"__outdword", "__indword",
	"__CFSHR__", "__CFSHL__", "__CFADD__", "__OFADD__", "__OFSUB__",
	"__SETP__", "__FSCALE__",
	"va_start", "va_end", "va_copy",
	"JUMPOUT", "BUG", "__halt", "_mm_mfence",
	"__readfsqword",
	"alloca",
	"memset", "memcpy", "memcmp", "memset32", "memset64",
	"qmemcpy", "qmemset",
	"strcmp", "strcpy", "strlen", "strcat",
	"wcscpy", "wcslen", "wcscat",
	"_bittest", "_bittest64", "_bittestandset64",
	"_BitScanReverse64", "_BitScanForward", "_BitScanReverse", "_BitScanForward64",
	"__fastfail", "__debugbreak", "__rdtsc",
	"NtCurrentPeb", "NtCurrentTeb",
	"_byteswap_ushort", "_byteswap_ulong", "_byteswap_uint64",
	"is_mul_ok", "saturated_mul",
	"__ROL1__", "__ROL2__", "__ROL4__", "__ROL8__",
	"__ROR1__", "__ROR2__", "__ROR4__", "__ROR8__",
	"__CS__", "__SS__", "__DS__", "__ES__", "__FS__", "__GS__", "MK_FP",
	"__readeflags", "__writeeflags", "__readfsdword", "__readgsdword", "__writegsdword",
	"__readgsqword",
	"fabs", "fminf", "fmaxf", "abs32", "abs64", "sqrt", "fmin", "fmax", "fsqrt",
}

coerces = {
	"COERCE_FLOAT", "COERCE_DOUBLE", "COERCE__INT64",
	"COERCE_UNSIGNED_INT", "COERCE_UNSIGNED_INT64",
}

interlocked_asg_helpers = {
	"_InterlockedExchange", "_InterlockedExchange8",
	"_InterlockedExchange16", "_InterlockedExchange32",
	"_InterlockedExchange64", "_InterlockedExchange128",
	"_InterlockedCompareExchange", "_InterlockedCompareExchange8",
	"_InterlockedCompareExchange16", "_InterlockedCompareExchange32",
	"_InterlockedCompareExchange64", "_InterlockedCompareExchange128",
}

interlocked_rv_helpers = {
	"_InterlockedAdd", "_InterlockedAdd8", "_InterlockedAdd16",
	"_InterlockedAdd32", "_InterlockedAdd64",
	"_InterlockedSub", "_InterlockedSub8", "_InterlockedSub16",
	"_InterlockedSub32", "_InterlockedSub64",
	"_InterlockedAnd", "_InterlockedAnd8",
	"_InterlockedAnd16", "_InterlockedAnd32",
	"_InterlockedAnd64",
	"_InterlockedOr", "_InterlockedOr8",
	"_InterlockedOr16", "_InterlockedOr32",
	"_InterlockedOr64",
	"_InterlockedXor", "_InterlockedXor8",
	"_InterlockedXor16", "_InterlockedXor32",
	"_InterlockedXor64",
	"_InterlockedDecrement", "_InterlockedDecrement8",
	"_InterlockedDecrement16", "_InterlockedDecrement32",
	"_InterlockedDecrement64",
	"_InterlockedIncrement", "_InterlockedIncrement8",
	"_InterlockedIncrement16", "_InterlockedIncrement32",
	"_InterlockedIncrement64",
	"_InterlockedExchangeAdd", "_InterlockedExchangeAdd8",
	"_InterlockedExchangeAdd16", "_InterlockedExchangeAdd32",
	"_InterlockedExchangeAdd64", "_InterlockedExchangeAdd128",
}


def is_known_call(func_expr:idaapi.cexpr_t, funcnames:set[str]) -> bool:
	if func_expr.op != idaapi.cot_call:
		return False

	called_func = func_expr.x
	if called_func.op == idaapi.cot_helper:
		funcname = called_func.helper

	elif called_func.op == idaapi.cot_obj and utils.is_func_start(called_func.obj_ea):
		func_addr = called_func.obj_ea
		if (target := utils.get_trampoline_func_target(func_addr)) == -1:
			funcname = idaapi.get_name(target)
		else:
			funcname = idaapi.get_name(func_addr)

	else:
		return False

	return funcname in funcnames


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
	return vars

def get_var_helper(expr:idaapi.cexpr_t, actx:ASTCtx) -> VarUseChain|None:
	if expr.op != idaapi.cot_call or expr.x.op != idaapi.cot_helper or len(expr.a) != 1:
		return None
	if (offset := helper2offset.get(expr.x.helper)) is None:
		return None

	if (var := get_var(expr.a[0], actx)) is None:
		return None

	return VarUseChain(var, VarUse(offset, VarUse.VAR_HELPER))

def get_var_use_chain(expr:idaapi.cexpr_t, actx:ASTCtx) -> VarUseChain|None:
	# FIXME
	if expr.op == idaapi.cot_num:
		return None

	if (var := get_var(expr, actx)) is not None:
		return VarUseChain(var)

	if len(extract_vars(expr, actx)) != 1:
		return None

	expr = utils.strip_casts(expr)
	if (var_helper := get_var_helper(expr, actx)) is not None:
		return var_helper

	op2use_type = {
		idaapi.cot_ptr: VarUse.VAR_PTR,
		idaapi.cot_memptr: VarUse.VAR_PTR,
		idaapi.cot_memref: VarUse.VAR_REF,
		idaapi.cot_ref: VarUse.VAR_REF,
		idaapi.cot_idx: VarUse.VAR_PTR,
		idaapi.cot_add: VarUse.VAR_ADD,
		idaapi.cot_sub: VarUse.VAR_ADD,
	}
	use_type = op2use_type.get(expr.op)
	if use_type is None:
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
			return None
		if expr.op == idaapi.cot_sub:
			offset = -offset
		if expr.x.type.is_ptr():
			pointed = expr.x.type.get_pointed_object()
			offset *= pointed.get_size()

	# this should not happen at all, since expr op is check when use_type gets got
	else:
		raise Exception("Wut")

	var_use = VarUse(offset, use_type)
	use_chain.append(var_use)
	return VarUseChain(var, *use_chain)


def is_exit_node(node:Node) -> bool:
	return len(node.children) == 0 and not node.is_return()

def iterate_exit_nodes(node:Node):
	if is_exit_node(node):
		yield node
		return

	for child in node.iterate_children():
		if is_exit_node(child):
			yield child

def chain_trees(*nodes:Node):
	if len(nodes) < 2:
		return

	for i in range(len(nodes) - 1):
		parent = nodes[i]
		child = nodes[i + 1]
		# must collect first, and then add new links
		for exit in [e for e in iterate_exit_nodes(parent)]:
			exit.children.add(child)
			child.parents.add(exit)

def chain_nodes(*nodes:Node):
	if len(nodes) < 2:
		return

	for i in range(len(nodes) - 1):
		parent = nodes[i]
		child = nodes[i + 1]
		parent.children.add(child)
		child.parents.add(parent)


class CTreeAnalyzer:
	def __init__(self, cfunc:idaapi.cfunc_t):
		self.cfunc = cfunc
		self.actx = ASTCtx.from_cfunc(cfunc)

	def lift_cfunc(self) -> TFG:
		entry = self.lift_instr(self.cfunc.body)
		return TFG(entry)

	def lift_instr(self, cinstr) -> Node:
		if cinstr.op == idaapi.cit_expr:
			entry, _ = self.lift_cexpr(cinstr.cexpr)
		elif cinstr.op == idaapi.cit_block:
			instr_entries = [self.lift_instr(i) for i in cinstr.cblock]
			entry = instr_entries[0]
			chain_trees(*instr_entries)
		elif cinstr.op == idaapi.cit_if:
			entry, exit = self.lift_cexpr(cinstr.cif.expr)
			ithen = self.lift_instr(cinstr.cif.ithen)
			if cinstr.cif.ielse is not None:
				ielse = self.lift_instr(cinstr.cif.ielse)
			else:
				ielse = NOP_NODE.copy()
			chain_nodes(exit, ithen)
			chain_nodes(exit, ielse)
		elif cinstr.op == idaapi.cit_for:
			entry, init_end = self.lift_cexpr(cinstr.cfor.init)
			expr_start, _ = self.lift_cexpr(cinstr.cfor.expr)
			step_start, _ = self.lift_cexpr(cinstr.cfor.step)
			cfor_entry = self.lift_instr(cinstr.cfor.body)
			chain_trees(init_end, expr_start, cfor_entry, step_start)
		elif cinstr.op == idaapi.cit_while:
			entry, exit = self.lift_cexpr(cinstr.cwhile.expr)
			cwhile_entry = self.lift_instr(cinstr.cwhile.body)
			chain_nodes(exit, cwhile_entry)
		elif cinstr.op == idaapi.cit_do:
			sexpr_entry = self.lift_cexpr(cinstr.cdo.expr)[0]
			entry = self.lift_instr(cinstr.cdo.body)
			chain_trees(entry, sexpr_entry)
		elif cinstr.op == idaapi.cit_return:
			entry, exit = self.lift_cexpr(cinstr.creturn.expr)
			exit.node_type = Node.RETURN
		elif cinstr.op == idaapi.cit_switch:
			# cinstr.cswitch.cases + cinstr.cswitch.expr
			entry = NOP_NODE.copy()
		elif cinstr.op in (idaapi.cit_asm, idaapi.cit_empty, idaapi.cit_goto, idaapi.cit_end, idaapi.cit_break, idaapi.cit_continue):
			entry = NOP_NODE.copy()
		else:
			entry = NOP_NODE.copy()
			utils.log_err(f"unknown instr operand {cinstr.opname}")

		return entry

	def lift_cexpr(self, expr:idaapi.cexpr_t) -> tuple[Node,Node]:
		"""
		returns tuple (tree_start, tree_end)
		tree_end holds type of final expr
		tree_start can be the same as tree_end
		"""
		while expr.op == idaapi.cot_cast:
			expr = expr.x

		trees = []

		def lift_reuse(expr:idaapi.cexpr_t) -> SExpr:
			"""
			get a tree and later reuse sexpr of end node
			if start and end are the same, then reusing both of them and no start is return
			if start and end are different, then add start to trees to chain later
			"""
			s,e = self.lift_cexpr(expr)
			if s is not e:
				e.remove_node()
				trees.append(s)
			return e.sexpr

		def append_expr(expr:SExpr):
			node = Node(Node.EXPR, expr)
			trees.append(node)

		def lift_append(expr:idaapi.cexpr_t) -> Node:
			s, e = self.lift_cexpr(expr)
			trees.append(s)
			return e

		if expr.op == idaapi.cot_asg:
			target = lift_reuse(expr.x)
			value = lift_reuse(expr.y)
			asg = SExpr.create_assign(expr.ea, target, value)
			type_node = Node(Node.EXPR, asg)

		elif expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_helper:
			helper = expr.x.helper
			if helper in known_helpers or helper.startswith("_mm_") or helper.startswith("_m_") or helper.startswith("sys_"):
				for i, arg in enumerate(expr.a):
					arg_sexpr = lift_reuse(arg)
					arg_cast = Node(Node.TYPE_CAST, arg_sexpr, expr.x.type.get_nth_arg(i))
					trees.append(arg_cast)
				type_node = SExpr.create_type_literal(expr.ea, expr.x.type.get_rettype())
				type_node = Node(Node.EXPR, type_node)

			elif helper in helper2offset:
				arg = lift_reuse(expr.a[0])
				offset = helper2offset[helper]
				size = helper2size[helper]
				arg = SExpr.create_partial(expr.ea, arg, offset, size)
				type_node = Node(Node.EXPR, arg)

			elif helper in combine_helpers:
				arg0 = lift_reuse(expr.a[0])
				arg1 = lift_reuse(expr.a[1])
				comb = SExpr.create_combine(expr.ea, arg0, arg1)
				type_node = Node(Node.EXPR, comb)

			elif helper in interlocked_asg_helpers:
				# if cmp xchg, then more info can be gained from comparand
				if len(expr.a) == 3:
					lift_append(expr.a[2])

				target = lift_reuse(expr.a[0])
				target = SExpr.create_ptr(expr.a[0].ea, target)
				value = lift_reuse(expr.a[1])
				asg = SExpr.create_assign(expr.ea, target, value)
				append_expr(asg)
				type_expr = SExpr.create_type_literal(expr.ea, expr.type.get_rettype())
				type_node = Node(Node.EXPR, type_expr)

			elif helper in interlocked_rv_helpers:
				target = lift_reuse(expr.a[0])
				target = SExpr.create_ptr(expr.a[0].ea, target)
				if len(expr.a) > 1:
					value = lift_reuse(expr.a[1])
				else:
					value = SExpr.create_type_literal(-1, utils.str2tif("int"))
				op = SExpr.create_rw_op(expr.ea, target, value)
				append_expr(op)
				type_expr = SExpr.create_type_literal(expr.ea, expr.type.get_rettype())
				type_node = Node(Node.EXPR, type_expr)

			elif helper == "va_arg":
				arg_sexpr = lift_reuse(expr.a[0])
				arg_cast = Node(Node.TYPE_CAST, arg_sexpr, expr.x.type.get_nth_arg(0))
				trees.append(arg_cast)
				type_node = SExpr.create_type_literal(expr.ea, expr.x.type.get_rettype())
				type_node = Node(Node.EXPR, type_node)

			# casts are skipped
			elif helper in coerces:
				type_node = lift_reuse(expr.a[0])
				type_node = Node(Node.EXPR, type_node)

			else:
				utils.log_warn(f"failed to lift helper={helper} {utils.expr2str(expr)} in {idaapi.get_name(self.actx.addr)}")
				type_node = NOP_NODE.copy()

		elif expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_obj and utils.is_func_import(expr.x.obj_ea):
			func_tif = idaapi.tinfo_t()
			idaapi.get_type(expr.x.obj_ea, func_tif, 0)
			if utils.is_tif_correct(func_tif) and func_tif.is_func():
				retval_tif = func_tif.get_rettype()
			else:
				retval_tif = utils.UNKNOWN_TYPE
			call_func = SExpr.create_type_literal(expr.x.ea, retval_tif)

			for arg_id, arg in enumerate(expr.a):
				arg = utils.strip_casts(arg)
				arg_sexpr = lift_reuse(arg)
				arg_type = func_tif.get_nth_arg(arg_id)
				type_cast = Node(Node.TYPE_CAST, arg_sexpr, arg_type)
				trees.append(type_cast)
			call = SExpr.create_call(expr.ea, call_func)
			type_node = Node(Node.EXPR, call)

		elif expr.op == idaapi.cot_call and expr.x.op != idaapi.cot_helper:
			call_func = lift_reuse(expr.x)
			for arg_id, arg in enumerate(expr.a):
				arg = utils.strip_casts(arg)
				arg_sexpr = lift_reuse(arg)
				call_cast = Node(Node.CALL_CAST, arg_sexpr, arg_id, call_func)
				trees.append(call_cast)
			call = SExpr.create_call(expr.ea, call_func)
			type_node = Node(Node.EXPR, call)

		elif expr.op == idaapi.cot_num:
			sint = SExpr.create_type_literal(expr.ea, expr.type)
			type_node = Node(Node.EXPR, sint)

		elif expr.op == idaapi.cot_sizeof:
			type_node = Node(Node.EXPR, SExpr.create_type_literal(expr.ea, utils.str2tif("int")))

		elif expr.op == idaapi.cot_obj and (utils.is_func_start(expr.obj_ea) or utils.is_func_import(expr.obj_ea)):
			func = SExpr.create_function(expr.ea, expr.obj_ea)
			type_node = Node(Node.EXPR, func)

		elif expr.op in bool_operations:
			lift_append(expr.x)
			lift_append(expr.y)
			boolop = SExpr.create_type_literal(expr.ea, utils.str2tif("bool"))
			type_node = Node(Node.EXPR, boolop)

		elif expr.op == idaapi.cot_lnot:
			lift_append(expr.x)
			boolop = SExpr.create_type_literal(expr.ea, utils.str2tif("bool"))
			type_node = Node(Node.EXPR, boolop)

		elif (vuc := get_var_use_chain(expr, self.actx)) is not None:
			vuc = SExpr.create_var_use_chain(expr.ea, vuc)
			type_node = Node(Node.EXPR, vuc)

		elif expr.op in int_rw_operations:
			target = lift_reuse(expr.x)
			value = SExpr.create_type_literal(-1, utils.str2tif("int"))
			sexpr = SExpr.create_rw_op(expr.ea, target, value)
			type_node = Node(Node.EXPR, sexpr)

		# -expr and ~expr do not change type
		elif expr.op in (idaapi.cot_neg, idaapi.cot_bnot, idaapi.cot_fneg):
			type_expr = lift_reuse(expr.x)
			type_node = Node(Node.EXPR, type_expr)

		elif expr.op == idaapi.cot_tern:
			lift_append(expr.x)
			x = lift_reuse(expr.y)
			y = lift_reuse(expr.z)
			tern = SExpr.create_tern(expr.ea, x, y)
			type_node = Node(Node.EXPR, tern)

		elif expr.op in value_rw_operations:
			target = lift_reuse(expr.x)
			value = lift_reuse(expr.y)
			sexpr = SExpr.create_rw_op(expr.ea, target, value)
			type_node = Node(Node.EXPR, sexpr)

		elif expr.op == idaapi.cot_ref:
			base = lift_reuse(expr.x)
			sexpr = SExpr.create_ref(expr.ea, base)
			type_node = Node(Node.EXPR, sexpr)

		elif expr.op == idaapi.cot_ptr:
			base = lift_reuse(expr.x)
			sexpr = SExpr.create_ptr(expr.ea, base)
			type_node = Node(Node.EXPR, sexpr)

		elif expr.op in binary_operations:
			x = lift_reuse(expr.x)
			y = lift_reuse(expr.y)
			binop = SExpr.create_binary_op(expr.ea, x, y)
			type_node = Node(Node.EXPR, binop)

		elif expr.op in (idaapi.cot_fadd, idaapi.cot_fdiv, idaapi.cot_fmul, idaapi.cot_fsub):
			lift_append(expr.x)
			lift_append(expr.y)
			fop = SExpr.create_type_literal(expr.ea, expr.type)
			type_node = Node(Node.EXPR, fop)

		elif expr.op == idaapi.cot_fnum:
			s = SExpr.create_type_literal(expr.ea, expr.type)
			type_node = Node(Node.EXPR, s)

		elif expr.op == idaapi.cot_str:
			s = SExpr.create_type_literal(expr.ea, utils.str2tif("char*"))
			type_node = Node(Node.EXPR, s)

		elif expr.op == idaapi.cot_empty:
			type_node = NOP_NODE.copy()

		elif expr.op == idaapi.cot_idx:
			arr = lift_reuse(expr.x)
			idx = lift_reuse(expr.y)
			if expr.x.type.is_ptr() and expr.y.type.is_integral(): # pointer arithmetics
				i = SExpr.create_type_literal(expr.x.ea, utils.str2tif("int"))
				idx = SExpr.create_binary_op(expr.x.ea, idx, i)
			add_expr = SExpr.create_binary_op(expr.x.ea, arr, idx)
			ptr_expr = SExpr.create_ptr(expr.ea, add_expr)
			type_node = Node(Node.EXPR, ptr_expr)

		elif expr.op == idaapi.cot_comma:
			lift_append(expr.x)
			type_node = lift_append(expr.y)

		elif expr.op == idaapi.cot_memptr:
			mem = lift_reuse(expr.x)
			base = SExpr.create_ptr(expr.ea, mem, expr.m)
			type_node = Node(Node.EXPR, base)

		elif expr.op == idaapi.cot_memref:
			sexpr = lift_reuse(expr.x)
			if sexpr.is_type_literal():
				type_expr = SExpr.create_type_literal(expr.ea, expr.type)

			# selecting union's field
			elif expr.type.is_union():
				type_expr = sexpr

			# expr.type.is_struct()
			# selecting structure's field
			else:
				i = SExpr.create_type_literal(-1, utils.str2tif("int"))
				type_expr = SExpr.create_binary_op(expr.ea, sexpr, i)

			type_node = Node(Node.EXPR, type_expr)

		# rogue stack reads
		elif expr.op == idaapi.cot_helper and expr.helper.startswith("STACK[0x"):
			type_node = NOP_NODE.copy()

		else:
			utils.log_warn(f"failed to lift {expr.opname} {utils.expr2str(expr)} in {idaapi.get_name(self.actx.addr)}")
			type_node = NOP_NODE.copy()

		trees.append(type_node)
		start = trees[0]
		chain_trees(*trees)
		return start, type_node