from __future__ import annotations

import idaapi

import pyphrank.utils as utils
from pyphrank.ast_parts import SExpr, ASTCtx, Node
from pyphrank.ast_parts import Var, VarUse, VarUseChain, UNKNOWN_SEXPR
from pyphrank.ast_analysis import ASTAnalysis


bool_operations = {
	idaapi.cot_bor, idaapi.cot_uge, idaapi.cot_band, idaapi.cot_sge,
	idaapi.cot_sgt, idaapi.cot_eq, idaapi.cot_ne, idaapi.cot_slt,
	idaapi.cot_land, idaapi.cot_sle, idaapi.cot_ult,
	idaapi.cot_ule, idaapi.cot_lor, idaapi.cot_ugt,
}

# idaapi.cot_lnot, idaapi.cot_neg

binary_operations = {
	idaapi.cot_mul, idaapi.cot_sub,
}

rw_operations = {
	idaapi.cot_postdec, idaapi.cot_predec, idaapi.cot_preinc,
	idaapi.cot_postinc, idaapi.cot_asgadd, idaapi.cot_asgmul,
	idaapi.cot_asgsub, idaapi.cot_asgbor,
}

helper2offset = {
	"HIBYTE": 1,
	"LOBYTE": 0,
	"HIWORD": 2,
	"LOWORD": 0,
	"HIDWORD": 4,
}


def is_known_call(func_expr:idaapi.cexpr_t, funcname:str) -> bool:
	if func_expr.op != idaapi.cot_call:
		return False

	x = func_expr.x
	if x.op == idaapi.cot_helper and x.helper == funcname:
		return True

	if x.op != idaapi.cot_obj or not utils.is_func_start(x.obj_ea):
		return False

	func_addr = x.obj_ea
	if idaapi.get_name(func_addr) == funcname:
		return True

	if (target := utils.get_trampoline_func_target(func_addr)) == -1:
		return False

	return idaapi.get_name(target) == funcname

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


def nop_node():
	return Node(Node.EXPR, UNKNOWN_SEXPR)

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
			exit.children.append(child)
			child.parents.append(exit)

def chain_nodes(*nodes:Node):
	if len(nodes) < 2:
		return

	for i in range(len(nodes) - 1):
		parent = nodes[i]
		child = nodes[i + 1]
		parent.children.append(child)
		child.parents.append(parent)


class CTreeAnalyzer:
	def __init__(self):
		self.ast_analysis_cache = {}
		self.actx = None

	def cache_analysis(self, analysis:ASTAnalysis):
		self.ast_analysis_cache[analysis.actx.addr] = analysis

	def get_ast_analysis(self, cfunc:idaapi.cfunc_t) -> ASTAnalysis:
		cached = self.ast_analysis_cache.get(cfunc.entry_ea)
		if cached is not None:
			return cached

		rv = self.lift_cfunc(cfunc)
		self.cache_analysis(rv)
		return rv

	def lift_cfunc(self, cfunc:idaapi.cfunc_t) -> ASTAnalysis:
		self.actx = ASTCtx.from_cfunc(cfunc)
		entry = self.lift_instr(cfunc.body)
		ast_analysis = ASTAnalysis(entry, self.actx)
		return ast_analysis

	def lift_instr(self, cinstr) -> Node:
		sexpr_nodes = []
		if cinstr.op == idaapi.cit_expr:
			sexpr_nodes = self.lift_cexpr(cinstr.cexpr)
			entry = sexpr_nodes[0]
		elif cinstr.op == idaapi.cit_block:
			instr_entries = [self.lift_instr(i) for i in cinstr.cblock]
			entry = instr_entries[0]
			chain_trees(*instr_entries)
		elif cinstr.op == idaapi.cit_if:
			sexpr_nodes = self.lift_cexpr(cinstr.cif.expr)
			entry = sexpr_nodes[0]
			exit = sexpr_nodes[-1]
			ithen = self.lift_instr(cinstr.cif.ithen)
			if cinstr.cif.ielse is not None:
				ielse = self.lift_instr(cinstr.cif.ielse)
			else:
				ielse = nop_node()
			chain_nodes(exit, ithen)
			chain_nodes(exit, ielse)
		elif cinstr.op == idaapi.cit_for:
			init_nodes = self.lift_cexpr(cinstr.cfor.init)
			expr_nodes = self.lift_cexpr(cinstr.cfor.expr)
			step_nodes = self.lift_cexpr(cinstr.cfor.step)
			cfor_entry = self.lift_instr(cinstr.cfor.body)
			entry = init_nodes[0]
			chain_trees(entry, expr_nodes[0], cfor_entry, step_nodes[0])
		elif cinstr.op == idaapi.cit_while:
			sexprs = self.lift_cexpr(cinstr.cwhile.expr)
			entry = sexprs[0]
			exit = sexprs[-1]
			cwhile_entry = self.lift_instr(cinstr.cwhile.body)
			chain_nodes(exit, cwhile_entry)
		elif cinstr.op == idaapi.cit_do:
			sexpr_entry = self.lift_cexpr(cinstr.cdo.expr)[0]
			entry = self.lift_instr(cinstr.cdo.body)
			chain_trees(entry, sexpr_entry)
		elif cinstr.op == idaapi.cit_return:
			sexpr_nodes = self.lift_cexpr(cinstr.creturn.expr)
			if len(sexpr_nodes) == 1:
				last_sexpr = sexpr_nodes.pop()
				return_node = Node(Node.RETURN, last_sexpr.sexpr)
				entry = return_node
			else:
				last_sexpr = sexpr_nodes.pop()
				return_node = Node(Node.RETURN, last_sexpr.sexpr)
				sexpr_nodes.append(return_node)
				entry = sexpr_nodes[0]
				chain_nodes(last_sexpr, return_node)
		elif cinstr.op == idaapi.cit_switch:
			# cinstr.cswitch.cases + cinstr.cswitch.expr
			entry = nop_node()
		elif cinstr.op in (idaapi.cit_asm, idaapi.cit_empty, idaapi.cit_goto, idaapi.cit_end, idaapi.cit_break, idaapi.cit_continue):
			entry = nop_node()
		else:
			entry = nop_node()
			utils.log_err(f"unknown instr operand {cinstr.opname}")

		return entry

	def lift_cexpr(self, expr:idaapi.cexpr_t) -> list[Node]:
		"""
		last node holds type of final expr
		returned nodes are chained
		returned list is always non-empty
		returned nodes do not contain return node
		"""
		if expr.op == idaapi.cot_cast:
			expr = expr.x

		if expr.op == idaapi.cot_asg:
			new_nodes = self.lift_cexpr(expr.x)
			target = new_nodes.pop().sexpr
			new_nodes += self.lift_cexpr(expr.y)
			value = new_nodes.pop().sexpr
			asg = SExpr.create_assign(expr.ea, target, value)
			node = Node(Node.EXPR, asg)
			new_nodes.append(node)

		elif expr.op == idaapi.cot_call and expr.x.op != idaapi.cot_helper:
			call_nodes = self.lift_cexpr(expr.x)
			call_func = call_nodes.pop().sexpr
			new_nodes = []
			for arg_id, arg in enumerate(expr.a):
				arg = utils.strip_casts(arg)
				new_nodes += self.lift_cexpr(arg)
				arg_sexpr = new_nodes.pop().sexpr
				call_cast = Node(Node.CALL_CAST, arg_sexpr, arg_id, call_func)
				new_nodes.append(call_cast)
			call = SExpr.create_call(expr.ea, call_func)
			node = Node(Node.EXPR, call)
			new_nodes.append(node)
			new_nodes += call_nodes

		elif is_known_call(expr, "memset"):
			new_nodes = self.lift_cexpr(expr.a[0])
			arg_sexpr = new_nodes.pop().sexpr
			n = utils.get_int(expr.a[2])
			if n is None:
				n = 1
			type_cast = Node(Node.TYPE_CAST, arg_sexpr, utils.str2tif(f"char [{n}]"))
			new_nodes.append(type_cast)
			# TODO potential type casts of arg1 and arg2
			node = nop_node()
			new_nodes.append(node)

		elif expr.op == idaapi.cot_num:
			sint = SExpr.create_int(expr.ea, expr.n._value, expr.type)
			node = Node(Node.EXPR, sint)
			new_nodes = [node]

		elif expr.op == idaapi.cot_obj and (utils.is_func_start(expr.obj_ea) or utils.is_func_import(expr.obj_ea)):
			func = SExpr.create_function(expr.ea, expr.obj_ea)
			node = Node(Node.EXPR, func)
			new_nodes = [node]

		elif expr.op in bool_operations:
			x_nodes = self.lift_cexpr(expr.x)
			x = x_nodes.pop().sexpr
			y_nodes = self.lift_cexpr(expr.y)
			y = y_nodes.pop().sexpr
			boolop = SExpr.create_bool_op(expr.ea, x, y)
			node = Node(Node.EXPR, boolop)
			new_nodes = x_nodes + y_nodes + [node]

		elif (vuc := get_var_use_chain(expr, self.actx)) is not None:
			vuc = SExpr.create_var_use_chain(expr.ea, vuc)
			node = Node(Node.EXPR, vuc)
			new_nodes = [node]

		elif expr.op in rw_operations:
			# TODO not implemented
			node = nop_node()
			new_nodes = [node]

		elif expr.op in binary_operations and len(extract_vars(expr, self.actx)) > 1:
			x_nodes = self.lift_cexpr(expr.x)
			x = x_nodes.pop().sexpr
			y_nodes = self.lift_cexpr(expr.y)
			y = y_nodes.pop().sexpr
			binop = SExpr.create_binary_op(expr.ea, x, y)
			node = Node(Node.EXPR, binop)
			new_nodes = x_nodes + y_nodes + [node]

		else:
			utils.log_warn(f"failed to lift {expr.opname} {utils.expr2str(expr)} in {idaapi.get_name(self.actx.addr)}")
			node = nop_node()
			new_nodes = [node]

		chain_nodes(*new_nodes)
		return new_nodes