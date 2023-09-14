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
	"SLODWORD": 0, 
	"BYTE1": 1,
	"BYTE2": 2,
	"HIBYTE": 4,
	"HIWORD": 2,
	"HIDWORD": 4,
	"SHIDWORD": 4,
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
		sexpr_nodes = []
		if cinstr.op == idaapi.cit_expr:
			sexpr_nodes = self.lift_cexpr(cinstr.cexpr, True)
			entry = sexpr_nodes[0]
		elif cinstr.op == idaapi.cit_block:
			instr_entries = [self.lift_instr(i) for i in cinstr.cblock]
			entry = instr_entries[0]
			chain_trees(*instr_entries)
		elif cinstr.op == idaapi.cit_if:
			sexpr_nodes = self.lift_cexpr(cinstr.cif.expr, True)
			entry = sexpr_nodes[0]
			exit = sexpr_nodes[-1]
			ithen = self.lift_instr(cinstr.cif.ithen)
			if cinstr.cif.ielse is not None:
				ielse = self.lift_instr(cinstr.cif.ielse)
			else:
				ielse = NOP_NODE.copy()
			chain_nodes(exit, ithen)
			chain_nodes(exit, ielse)
		elif cinstr.op == idaapi.cit_for:
			init_nodes = self.lift_cexpr(cinstr.cfor.init, True)
			expr_nodes = self.lift_cexpr(cinstr.cfor.expr, True)
			step_nodes = self.lift_cexpr(cinstr.cfor.step, True)
			cfor_entry = self.lift_instr(cinstr.cfor.body)
			entry = init_nodes[0]
			chain_trees(entry, expr_nodes[0], cfor_entry, step_nodes[0])
		elif cinstr.op == idaapi.cit_while:
			sexprs = self.lift_cexpr(cinstr.cwhile.expr, True)
			entry = sexprs[0]
			exit = sexprs[-1]
			cwhile_entry = self.lift_instr(cinstr.cwhile.body)
			chain_nodes(exit, cwhile_entry)
		elif cinstr.op == idaapi.cit_do:
			sexpr_entry = self.lift_cexpr(cinstr.cdo.expr, True)[0]
			entry = self.lift_instr(cinstr.cdo.body)
			chain_trees(entry, sexpr_entry)
		elif cinstr.op == idaapi.cit_return:
			sexpr_nodes = self.lift_cexpr(cinstr.creturn.expr, False)
			last_sexpr = sexpr_nodes.pop().sexpr
			if len(sexpr_nodes) == 0:
				entry = Node(Node.RETURN, last_sexpr)
			else:
				return_node = Node(Node.RETURN, last_sexpr)
				entry = sexpr_nodes[0]
				chain_nodes(*sexpr_nodes, return_node)
		elif cinstr.op == idaapi.cit_switch:
			# cinstr.cswitch.cases + cinstr.cswitch.expr
			entry = NOP_NODE.copy()
		elif cinstr.op in (idaapi.cit_asm, idaapi.cit_empty, idaapi.cit_goto, idaapi.cit_end, idaapi.cit_break, idaapi.cit_continue):
			entry = NOP_NODE.copy()
		else:
			entry = NOP_NODE.copy()
			utils.log_err(f"unknown instr operand {cinstr.opname}")

		return entry

	def lift_cexpr(self, expr:idaapi.cexpr_t, should_chain:bool) -> list[Node]:
		"""
		last node holds type of final expr
		returned nodes are chained, if should_chain is True
		returned list is always non-empty
		returned nodes do not contain return node
		"""
		if expr.op == idaapi.cot_cast:
			expr = expr.x

		if expr.op == idaapi.cot_asg:
			new_nodes = self.lift_cexpr(expr.x, False)
			target = new_nodes.pop().sexpr
			new_nodes += self.lift_cexpr(expr.y, False)
			value = new_nodes.pop().sexpr
			asg = SExpr.create_assign(expr.ea, target, value)
			node = Node(Node.EXPR, asg)
			new_nodes.append(node)

		elif is_known_call(expr, settings.memset_funcs):
			new_nodes = self.lift_cexpr(expr.a[0], False)
			arg_sexpr = new_nodes.pop().sexpr
			n = utils.get_int(expr.a[2])
			if n is None:
				n = 1
			type_cast = Node(Node.TYPE_CAST, arg_sexpr, utils.str2tif(f"char [{n}]"))
			new_nodes.append(type_cast)
			# TODO potential type casts of arg1 and arg2
			node = NOP_NODE.copy()
			new_nodes.append(node)

		elif expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_obj and utils.is_func_import(expr.x.obj_ea):
			func_tif = idaapi.tinfo_t()
			idaapi.get_type(expr.x.obj_ea, func_tif, 0)
			if utils.is_tif_correct(func_tif) and func_tif.is_func():
				tif = func_tif.get_rettype()
			else:
				tif = utils.UNKNOWN_TYPE
			call_func = SExpr.create_type_literal(expr.x.ea, tif)

			new_nodes = []
			for arg_id, arg in enumerate(expr.a):
				arg = utils.strip_casts(arg)
				new_nodes += self.lift_cexpr(arg, False)
				arg_sexpr = new_nodes.pop().sexpr
				arg_type = func_tif.get_nth_arg(arg_id)
				type_cast = Node(Node.TYPE_CAST, arg_sexpr, arg_type)
				new_nodes.append(type_cast)
			call = SExpr.create_call(expr.ea, call_func)
			node = Node(Node.EXPR, call)
			new_nodes.append(node)

		elif expr.op == idaapi.cot_call and expr.x.op != idaapi.cot_helper:
			call_nodes = self.lift_cexpr(expr.x, False)
			call_func = call_nodes.pop().sexpr
			new_nodes = []
			for arg_id, arg in enumerate(expr.a):
				arg = utils.strip_casts(arg)
				new_nodes += self.lift_cexpr(arg, False)
				arg_sexpr = new_nodes.pop().sexpr
				call_cast = Node(Node.CALL_CAST, arg_sexpr, arg_id, call_func)
				new_nodes.append(call_cast)
			call = SExpr.create_call(expr.ea, call_func)
			node = Node(Node.EXPR, call)
			new_nodes += call_nodes
			new_nodes.append(node)

		elif expr.op == idaapi.cot_num:
			sint = SExpr.create_type_literal(expr.ea, expr.type)
			node = Node(Node.EXPR, sint)
			new_nodes = [node]

		elif expr.op == idaapi.cot_obj and (utils.is_func_start(expr.obj_ea) or utils.is_func_import(expr.obj_ea)):
			func = SExpr.create_function(expr.ea, expr.obj_ea)
			node = Node(Node.EXPR, func)
			new_nodes = [node]

		elif expr.op in bool_operations:
			x_nodes = self.lift_cexpr(expr.x, False)
			y_nodes = self.lift_cexpr(expr.y, False)
			boolop = SExpr.create_type_literal(expr.ea, utils.str2tif("bool"))
			node = Node(Node.EXPR, boolop)
			new_nodes = x_nodes + y_nodes + [node]

		elif expr.op == idaapi.cot_lnot:
			new_nodes = self.lift_cexpr(expr.x, False)
			boolop = SExpr.create_type_literal(expr.ea, utils.str2tif("bool"))
			node = Node(Node.EXPR, boolop)
			new_nodes.append(node)

		elif (vuc := get_var_use_chain(expr, self.actx)) is not None:
			vuc = SExpr.create_var_use_chain(expr.ea, vuc)
			node = Node(Node.EXPR, vuc)
			new_nodes = [node]

		elif expr.op in int_rw_operations:
			target_nodes = self.lift_cexpr(expr.x, False)
			target = target_nodes.pop().sexpr
			value = SExpr.create_type_literal(-1, utils.str2tif("int"))
			sexpr = SExpr.create_rw_op(expr.ea, target, value)
			node = Node(Node.EXPR, sexpr)
			new_nodes = target_nodes + [node]

		# cot_neg does not change type
		elif expr.op == idaapi.cot_neg:
			new_nodes = self.lift_cexpr(expr.x, should_chain=False)

		elif expr.op in value_rw_operations:
			target_nodes = self.lift_cexpr(expr.x, False)
			target = target_nodes.pop().sexpr
			value_nodes = self.lift_cexpr(expr.y, False)
			value = value_nodes.pop().sexpr
			sexpr = SExpr.create_rw_op(expr.ea, target, value)
			node = Node(Node.EXPR, sexpr)
			new_nodes = target_nodes + value_nodes + [node]

		elif expr.op == idaapi.cot_ref:
			assert expr.x is not None
			base_nodes = self.lift_cexpr(expr.x, False)
			base = base_nodes.pop().sexpr
			sexpr = SExpr.create_ref(expr.ea, base)
			node = Node(Node.EXPR, sexpr)
			new_nodes = base_nodes + [node]

		elif expr.op == idaapi.cot_ptr:
			assert expr.x is not None
			base_nodes = self.lift_cexpr(expr.x, False)
			base = base_nodes.pop().sexpr
			sexpr = SExpr.create_ptr(expr.ea, base)
			node = Node(Node.EXPR, sexpr)
			new_nodes = base_nodes + [node]

		elif expr.op in binary_operations:
			x_nodes = self.lift_cexpr(expr.x, False)
			x = x_nodes.pop().sexpr
			y_nodes = self.lift_cexpr(expr.y, False)
			y = y_nodes.pop().sexpr
			binop = SExpr.create_binary_op(expr.ea, x, y)
			node = Node(Node.EXPR, binop)
			new_nodes = x_nodes + y_nodes + [node]

		else:
			utils.log_warn(f"failed to lift {expr.opname} {utils.expr2str(expr)} in {idaapi.get_name(self.actx.addr)}")
			print(f"failed to lift {expr.opname} {utils.expr2str(expr)} in {idaapi.get_name(self.actx.addr)}")
			node = NOP_NODE.copy()
			new_nodes = [node]

		if should_chain:
			chain_nodes(*new_nodes)
		return new_nodes