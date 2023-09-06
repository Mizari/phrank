from __future__ import annotations

import idc
import idaapi

from pyphrank.function_manager import FunctionManager
from pyphrank.type_flow_graph_parts import Var, SExpr, VarUseChain, Node, UNKNOWN_SEXPR, NOP_NODE
from pyphrank.containers.structure import Structure
from pyphrank.ast_analyzer import TFG, chain_nodes
from pyphrank.analysis_state import AnalysisState
from pyphrank.container_manager import ContainerManager
from pyphrank.type_constructors.type_constructor_interface import ITypeConstructor
from pyphrank.type_constructors.vtable_constructor import VtableConstructor
from pyphrank.type_constructors.struct_constructor import StructConstructor
import pyphrank.utils as utils


def select_type(*tifs):
	if len(tifs) == 0:
		utils.log_warn(f"trying to select type from 0 types")
		return utils.UNKNOWN_TYPE

	# single assign can only be one type
	if len(tifs) == 1:
		return tifs[0]

	# try to resolve multiple assigns
	# prefer types over non-types
	strucid_assign_types = []
	others = []
	for tif in tifs:
		if tif is utils.UNKNOWN_TYPE:
			continue

		strucid = utils.tif2strucid(tif)
		if strucid != -1:
			if tif not in strucid_assign_types:
				strucid_assign_types.append(tif)
		elif tif not in others:
			others.append(tif)

	if len(strucid_assign_types) == 1:
		return strucid_assign_types[0]

	# multiple different strucid types is unknown
	if len(strucid_assign_types) > 0:
		return utils.UNKNOWN_TYPE

	if len(others) == 0:
		return utils.UNKNOWN_TYPE
	
	if len(others) == 1:
		return others[0]
	
	if all(tif.is_integral() for tif in others):
		max_size_int = others[0]
		for i in range(1, len(others)):
			if others[i].get_size() > max_size_int.get_size():
				max_size_int = others[i]
		return max_size_int
	return utils.UNKNOWN_TYPE

def is_typeful_node(node:Node) -> bool:
	""" Typeful node is a node, that can affect types """
	if node.is_call_cast() and node.sexpr.is_int():
		return False
	if node.is_expr() and node.sexpr.is_explicit_call():
		return False
	if node.is_expr() and node.sexpr is UNKNOWN_SEXPR:
		return False
	return True

def shrink_tfg(aa:TFG):
	def remove_node(node:Node):
		for parent in node.parents:
			parent.children.remove(node)
		for child in node.children:
			child.parents.remove(node)
		for parent in node.parents:
			for child in node.children:
				parent.children.add(child)
				child.parents.add(parent)

	bad_nodes = {n for n in aa.entry.iterate_children() if not is_typeful_node(n)}
	for node in bad_nodes:
		remove_node(node)

	entry = aa.entry
	if not is_typeful_node(entry):
		if len(entry.children) == 1:
			# shift entry by one node down
			new_entry = entry.children.pop()
			new_entry.parents.clear()
		else:
			# replace entry
			new_entry = NOP_NODE.copy()
			for child in entry.children:
				new_entry.children.add(child)
				child.parents.remove(entry)
				child.parents.add(new_entry)
			entry.children.clear()

		aa.entry = new_entry


class TypeAnalyzer:
	def __init__(self) -> None:
		self.func_manager = FunctionManager()
		self.container_manager = ContainerManager()
		self.tfg_cache : dict[int,TFG ]= {}

		self.state = AnalysisState()

		self.constructors: list[ITypeConstructor] = [
			VtableConstructor(),
			StructConstructor(self),
		]

	def cache_tfg(self, addr:int, analysis:TFG):
		self.tfg_cache[addr] = analysis

	def get_tfg(self, func_ea:int) -> TFG:
		cached = self.tfg_cache.get(func_ea)
		if cached is not None:
			return cached

		aa = self.func_manager.get_tfg(func_ea)
		shrink_tfg(aa)
		self.tfg_cache[func_ea] = aa
		return aa

	def get_db_var_type(self, var:Var) -> idaapi.tinfo_t:
		if var.is_local():
			return self.func_manager.get_cfunc_lvar_type(var.func_ea, var.lvar_id)
		else:
			return utils.addr2tif(var.obj_ea)

	def set_db_var_type(self, var:Var, var_type:idaapi.tinfo_t):
		if var.is_local():
			self.func_manager.set_lvar_tinfo(var.func_ea, var.lvar_id, var_type)
		else:
			rv = idc.SetType(var.obj_ea, str(var_type) + ';')
			if rv == 0:
				utils.log_warn(f"setting {hex(var.obj_ea)} to {var_type} failed")

	def skip_analysis(self):
		# delete new temporarily created types
		self.container_manager.delete_containers()

		self.state.clear()

	def apply_analysis(self):
		for struct in self.container_manager.new_types.values():
			offsets = [o for o in struct.member_offsets()]
			if offsets == [0]:
				utils.log_err(f"{struct.name} has only one member at offset 0, most likely this is analysis error")

		touched_functions = set()
		for var in self.state.vars.keys():
			touched_functions.update(var.get_functions())

		new_xrefs = []
		for func_ea in touched_functions:
			func_aa = self.get_tfg(func_ea)
			for func_call in func_aa.iterate_implicit_calls():
				frm = func_call.expr_ea
				if frm == idaapi.BADADDR:
					continue

				call_ea = self.get_call_address(func_call.function)
				if call_ea == -1:
					continue

				new_xrefs.append((frm, call_ea))

		for frm, to in new_xrefs:
			rv = idaapi.add_cref(frm, to, idaapi.fl_CN)
			if not rv:
				utils.log_warn(f"failed to add code reference from {hex(frm)} to {hex(to)}")

		for var, new_type_tif in self.state.vars.items():
			if new_type_tif is utils.UNKNOWN_TYPE:
				continue

			self.set_db_var_type(var, new_type_tif)

		self.state.clear()
		# new types are already created, simply skip them without deleting
		self.container_manager.clear()

	def analyze_var(self, var:Var) -> idaapi.tinfo_t:
		current_lvar_tinfo = self.state.get_var(var, default=None)
		if current_lvar_tinfo is not None:
			return current_lvar_tinfo

		var_tinfo = self.analyze_by_heuristics(var)
		if var_tinfo is not utils.UNKNOWN_TYPE:
			self.state.vars[var] = var_tinfo
			return var_tinfo

		self.state.vars[var] = utils.UNKNOWN_TYPE # to break recursion

		var_uses = self.get_all_var_uses(var)
		if var_uses.uses_len(var) == 0:
			utils.log_warn(f"found no var uses for {var}")
			return utils.UNKNOWN_TYPE

		moves_types = []
		for m in var_uses.iterate_moves_to(var):
			mtype = self.analyze_sexpr_type(m)
			if mtype not in moves_types:
				moves_types.append(mtype)

		if var.is_local() and var.lvar_id < self.func_manager.get_args_count(var.func_ea) and len(moves_types) != 0:
			utils.log_err(f"argument {var} has moves to it, will most likely result in incorrect analysis")

		if len(moves_types) != 0 and (var_tinfo := select_type(*moves_types)) is not utils.UNKNOWN_TYPE:
			self.state.vars[var] = var_tinfo
			self.propagate_var(var)
			return var_tinfo

		if self.analyze_unknown_type_by_var_uses(var, var_uses):
			self.state.vars[var] = utils.UNKNOWN_TYPE
			return utils.UNKNOWN_TYPE

		var_tinfo = self.analyze_existing_type_by_var_uses(var, var_uses)
		if var_tinfo is not utils.UNKNOWN_TYPE:
			self.state.vars[var] = var_tinfo
			return var_tinfo

		for cont in self.constructors:
			if (lvar_struct := cont.from_tfg(var, var_uses)) is None:
				continue

			self.container_manager.add_struct(lvar_struct)
			var_tinfo = lvar_struct.ptr_tinfo
			self.add_type_uses_to_var(var, var_uses, var_tinfo)
			self.state.vars[var] = var_tinfo
			return var_tinfo

		return utils.UNKNOWN_TYPE

	def analyze_retval(self, func_ea:int) -> idaapi.tinfo_t:
		rv = self.state.retvals.get(func_ea)
		if rv is not None:
			return rv
		self.state.retvals[func_ea] = utils.UNKNOWN_TYPE # to break recursion

		aa = self.get_tfg(func_ea)
		r_types = [self.analyze_sexpr_type(r) for r in aa.iterate_return_sexprs()]
		retval_type = select_type(*r_types)
		self.state.retvals[func_ea] = retval_type
		return retval_type

	def analyze_sexpr_type(self, sexpr:SExpr) -> idaapi.tinfo_t:
		if sexpr.var_use_chain is not None:
			vuc = sexpr.var_use_chain
			tif = self.analyze_var(vuc.var)
			if tif is utils.UNKNOWN_TYPE:
				return tif
			stype = vuc.transform_type(tif)
			if isinstance(stype, utils.ShiftedStruct):
				stype = stype.tif
			return stype

		elif sexpr.is_function():
			return self.func_manager.get_func_tinfo(sexpr.func_addr)

		elif sexpr.is_explicit_call():
			return self.analyze_retval(sexpr.function.func_addr)

		elif sexpr.is_implicit_call():
			addr = self.get_call_address(sexpr.function) # type:ignore
			if addr != -1:
				return self.analyze_retval(addr)

			stype = self.analyze_sexpr_type(sexpr.function) # type:ignore
			if stype.is_funcptr():
				pointed_stype = stype.get_pointed_object()
				rettype = pointed_stype.get_rettype()
				return rettype
			if stype.is_func():
				return stype.get_rettype()

		elif sexpr.is_int():
			return sexpr.tif

		utils.log_warn(f"unknown sexpr value in {idaapi.get_name(sexpr.func_ea)}")
		return utils.UNKNOWN_TYPE

	def propagate_var(self, var:Var):
		var_type = self.state.get_var(var)
		if utils.tif2strucid(var_type) == -1:
			return

		var_uses = self.get_all_var_uses(var)
		for target in var_uses.iterate_moves_from(var):
			if (target_var := target.var) is None:
				continue
			self.propagate_type_to_var(target_var, var_type)

		for call_cast in var_uses.iterate_call_cast_nodes():
			call_ea = self.get_call_address(call_cast.func_call)
			if call_ea == -1:
				continue

			if utils.is_func_import(call_ea):
				continue

			if not call_cast.sexpr.is_var():
				continue

			arg_var = Var(call_ea, call_cast.arg_id)
			self.propagate_type_to_var(arg_var, var_type)

	def propagate_type_to_var(self, var:Var, new_type:idaapi.tinfo_t):
		current_type = self.state.get_var(var)
		if current_type is utils.UNKNOWN_TYPE:
			lvar_uses = self.get_all_var_uses(var)
			self.state.vars[var] = new_type
			self.propagate_var(var)
			self.add_type_uses_to_var(var, lvar_uses, new_type)
			return

		if current_type != new_type:
			utils.log_warn(
				f"failed to propagate {new_type} "\
				f"to {var} "\
				f"because variable has different type {current_type}"
			)

	def get_func_var_uses(self, func_ea:int, var:Var) -> TFG:
		aa = self.get_tfg(func_ea).copy()
		node_replacements : dict[Node, list[Node]] = {}
		for node in aa.iterate_nodes():
			sexpr = node.sexpr
			if var not in sexpr.extract_vars():
				node_replacements[node] = [NOP_NODE.copy()]
				continue

			if sexpr.is_var_use(var):
				continue

			if node.is_expr() and sexpr.is_assign():
				# writing into var or moving to var is OK
				if sexpr.target.is_var_use(var):
					continue

				if sexpr.value.is_var_use(var):
					# moving from var is OK
					if sexpr.value.is_var(var):
						continue

					# otherwise var read is OK, no need to know where this is read
					new_node = Node(Node.EXPR, sexpr.value)
					node_replacements[node] = [new_node]
					continue

			new_nodes = []
			for vuc in sexpr.extract_var_use_chains():
				if vuc.var != var:
					continue
				new_node = Node(Node.EXPR, SExpr.create_var_use_chain(-1, vuc))
				new_nodes.append(new_node)
			chain_nodes(*new_nodes)
			node_replacements[node] = new_nodes

		for node, new_nodes in node_replacements.items():
			first = new_nodes[0]
			for parent in node.parents:
				parent.children.remove(node)
				parent.children.add(first)
				first.parents.add(parent)

			last = new_nodes[-1]
			for child in node.children:
				child.parents.remove(node)
				child.parents.add(last)
				last.children.add(child)

		if aa.entry in node_replacements:
			aa.entry = node_replacements[aa.entry][0]
		shrink_tfg(aa)
		return aa

	def get_all_var_uses(self, var:Var) -> TFG:
		funcs = var.get_functions()
		if len(funcs) == 1:
			func_ea = funcs.pop()
			return self.get_func_var_uses(func_ea, var)

		new_entry = NOP_NODE.copy()
		for func_ea in funcs:
			va = self.get_func_var_uses(func_ea, var)
			new_entry.children.add(va.entry)
			va.entry.parents.add(new_entry)
		return TFG(new_entry)

	def analyze_by_heuristics(self, var:Var) -> idaapi.tinfo_t:
		original_var_tinfo = self.get_db_var_type(var)
		if utils.tif2strucid(original_var_tinfo) != -1:
			# TODO check correctness of writes, read, casts
			return original_var_tinfo

		# local/global specific analysis
		if var.is_local():
			cfunc_lvar = self.func_manager.get_cfunc_lvar(var.func_ea, var.lvar_id)
			if cfunc_lvar is not None and cfunc_lvar.is_stk_var() and not cfunc_lvar.is_arg_var:
				return utils.UNKNOWN_TYPE

			if utils.is_func_import(var.func_ea):
				return original_var_tinfo

		else:
			for ctor in self.constructors:
				if (struc := ctor.from_data(var.obj_ea)) is not None:
					self.container_manager.add_struct(struc)
					return struc.tinfo
		return utils.UNKNOWN_TYPE

	def analyze_unknown_type_by_var_uses(self, var:Var, var_uses:TFG) -> bool:
		def is_unknown_use_node(node:Node) -> bool:
			sexpr = node.sexpr
			if node.is_expr() and sexpr is UNKNOWN_SEXPR:
				return True

			# single read or move from var is unknown
			if node.is_expr() and sexpr.is_var_use(var):
				return True

			# single read or move from var is unknown
			if node.is_expr() and sexpr.is_assign() and var not in sexpr.target.extract_vars():
				return True

			# single read or move from var is unknown
			if node.is_return() and sexpr.is_var_use(var):
				return True

			# casting to unknown is unknown
			if node.is_call_cast():
				addr = self.analyze_call_address(node.func_call)
				if addr == -1:
					return True
				arg = Var(addr, node.arg_id)
				if self.analyze_var(arg) is utils.UNKNOWN_TYPE:
					return True

			# moving unknown to var is unknown
			if node.is_expr() and sexpr.is_move_to_var(var):
				return self.analyze_sexpr_type(sexpr.value) is utils.UNKNOWN_TYPE

			# writing unknown into var is unknown
			if node.is_expr() and sexpr.is_var_write(var):
				return self.analyze_sexpr_type(sexpr.value) is utils.UNKNOWN_TYPE

			return False

		if all(is_unknown_use_node(node) for node in var_uses.iterate_nodes()):
			return True

		return False

	def analyze_existing_type_by_var_uses(self, var:Var, var_uses:TFG) -> idaapi.tinfo_t:
		if not self.is_var_possible_ptr(var, var_uses):
			return utils.UNKNOWN_TYPE

		rw_ptr_uses = set()
		max_ptr_offset = 0
		for w in var_uses.iterate_var_writes(var):
			vuc = w.target.var_use_chain
			if vuc is None:
				continue
			write_offset = vuc.get_ptr_offset()
			if write_offset is None:
				continue
			rw_ptr_uses.add(write_offset)
			write_type = self.analyze_sexpr_type(w.value)
			if write_type is utils.UNKNOWN_TYPE:
				# TODO get original write size write_end = max(1, orig_sz)
				write_sz = 1
			else:
				write_sz = write_type.get_size()
				if write_sz == idaapi.BADSIZE:
					write_sz = 1
					utils.log_warn(f"failed to calculate write size of {str(write_type)}, using size=1")
			max_ptr_offset = max(max_ptr_offset, write_offset + write_sz)
		for r in var_uses.iterate_var_reads(var):
			if r.var_use_chain is None or (read_offset := r.var_use_chain.get_ptr_offset()) is None:
				continue
			rw_ptr_uses.add(read_offset)
			max_ptr_offset = max(max_ptr_offset, read_offset)

		if var_uses.casts_len(var) == 0:
			# cant determine ptr use without writes to it
			if len([w for w in var_uses.iterate_var_writes(var)]) == 0:
				return utils.UNKNOWN_TYPE

			# ptr uses other than offset0 create new type
			if rw_ptr_uses != {0}:
				return utils.UNKNOWN_TYPE

			write_types = [self.analyze_sexpr_type(w.value) for w in var_uses.iterate_var_writes(var)]
			write_type = select_type(*write_types)
			if write_type is utils.UNKNOWN_TYPE:
				return utils.UNKNOWN_TYPE
			write_type.create_ptr(write_type)
			return write_type

		if var_uses.casts_len(var) != 1:
			return utils.UNKNOWN_TYPE

		call_casts = [c for c in var_uses.iterate_call_cast_nodes()]
		type_casts = [c for c in var_uses.iterate_type_cast_nodes()]
		if len(call_casts) == 1:
			cast = call_casts[0]
			cast_arg = cast.sexpr
			addr = self.get_call_address(cast.func_call)
			if addr == -1:
				arg_type = utils.UNKNOWN_TYPE
			else:
				arg_var = Var(addr, cast.arg_id)
				arg_type = self.analyze_var(arg_var)
		else:
			cast_arg = type_casts[0].sexpr
			arg_type = type_casts[0].tif

		# offseted cast yields new type
		if not cast_arg.is_var():
			return utils.UNKNOWN_TYPE

		# if no other uses but single cast
		if var_uses.uses_len(var) == 1:
			return arg_type

		# single cast and writes into casted type
		if arg_type.is_ptr():
			arg_size = arg_type.get_pointed_object().get_size()
		else:
			arg_size = arg_type.get_size()

		if arg_size == idaapi.BADSIZE:
			utils.log_warn(f"failed to calculate size of argument {str(arg_type)}")
			return utils.UNKNOWN_TYPE

		# have use outside of type => new type
		if max_ptr_offset > arg_size:
			return utils.UNKNOWN_TYPE

		# otherwise not new type
		# TODO check incompatible uses, should create new type if found
		else:
			self.add_type_uses_to_var(var, var_uses, arg_type)
			return arg_type

	def add_type_uses_to_var(self, var:Var, var_uses:TFG, var_type:idaapi.tinfo_t):
		for node in var_uses.iterate_nodes():
			sexpr = node.sexpr
			# nop node
			if node.is_expr() and sexpr is UNKNOWN_SEXPR:
				continue

			if node.is_expr() and sexpr.is_assign():
				target1 = sexpr.target.var_use_chain
				# skip complex targets and simple
				if target1 is None or len(target1) == 0:
					continue

				# write nodes
				value = sexpr.value
				write_type = self.analyze_sexpr_type(value)
				target = self.analyze_target(var_type, target1)
				if target is None:
					utils.log_warn(f"cant add member={write_type} to type={var_type} from write {target}")
					continue
				self.container_manager.add_member_type(target.strucid, target.offset, write_type)

				if value.is_function():
					addr = value.function
					self.container_manager.add_member_name(target.strucid, target.offset, idaapi.get_name(addr))
				continue

			vuc = sexpr.var_use_chain
			if vuc is None or vuc.var != var:
				continue

			# assigns are handled, only read exprs are left
			if node.is_expr() or node.is_return():
				target = self.analyze_target(var_type, vuc)
				if target is None:
					utils.log_warn(f"cant read type={var_type} from expr {vuc}")
					continue
				self.container_manager.add_member_type(target.strucid, target.offset, utils.UNKNOWN_TYPE)

			elif node.is_call_cast():
				address = self.analyze_call_address(node.func_call)
				if address == -1:
					continue

				cast_var = Var(address, node.arg_id)
				if len(vuc) != 0:
					cast_type = self.analyze_var(cast_var)
					self.add_type_cast(vuc, cast_type, var_type)
					continue

				cast_type = self.state.get_var(var)
				if cast_type == var_type:
					continue

				if cast_type is not utils.UNKNOWN_TYPE:
					self.add_type_cast(vuc, cast_type, var_type)
					continue

				cast_var_uses = self.get_all_var_uses(cast_var)
				# if single call xref to addr
				if not utils.is_method(address) and len(utils.get_func_calls_to(address)) == 1:
					self.propagate_type_to_var(cast_var, var_type)
					self.add_type_uses_to_var(cast_var, cast_var_uses, var_type)
					continue

				# if existing type
				if (cast_type := self.analyze_var(cast_var)) is not utils.UNKNOWN_TYPE:
					self.state.vars[cast_var] = cast_type
					self.add_type_cast(vuc, cast_type, var_type)
					continue

				# TODO check if conflicting uses

			elif node.is_type_cast():
				self.add_type_cast(vuc, node.tif, var_type)

			else:
				# unexpected
				pass

	def add_type_cast(self, cast_arg:VarUseChain, cast_type:idaapi.tinfo_t, var_type:idaapi.tinfo_t):
		tif = cast_arg.transform_type(var_type)
		if isinstance(tif, utils.ShiftedStruct):
			self.container_manager.add_member_type(tif.strucid, tif.offset, cast_type)
			return

		base, offset = utils.get_shifted_base(tif)
		if base is not None and utils.is_struct_ptr(base):
			strucid = utils.tif2strucid(base)
			if cast_type is utils.UNKNOWN_TYPE:
				self.container_manager.add_member_type(strucid, offset, cast_type)
				return
			elif cast_type.is_ptr():
				self.container_manager.add_member_type(strucid, offset, cast_type.get_pointed_object())
				return
			elif cast_type.is_array():
				self.container_manager.add_member_type(strucid, offset, cast_type)
				return

		utils.log_warn(f"cant cast {var_type} transformed by {cast_arg} into {tif} to {cast_type}")

	def analyze_target(self, var_type:idaapi.tinfo_t, target:VarUseChain) -> utils.ShiftedStruct|None:
		tif = target.transform_type(var_type)
		if isinstance(tif, utils.ShiftedStruct):
			return tif

		# kostyl for UNKNOWN member pointer
		if utils.is_struct_ptr(var_type) and (offset := target.get_ptr_offset()) is not None:
			strucid = utils.tif2strucid(var_type)
			if strucid == -1:
				return None
			return utils.ShiftedStruct(strucid, offset)
		return None

	def analyze_call_address(self, func_call:SExpr) -> int:
		if func_call.is_function():
			return func_call.func_addr

		if (vuc := func_call.var_use_chain) is None:
			return -1

		if (var_tif := self.analyze_var(vuc.var)) is utils.UNKNOWN_TYPE:
			return -1

		member = vuc.transform_type(var_tif)
		if isinstance(member, utils.ShiftedStruct):
			addr = utils.str2addr(member.comment)
			if addr == -1:
				addr = utils.str2addr(member.name)
		else:
			addr = -1
			utils.log_warn(f"failed to get final member from {var_tif} {vuc}")

		return addr

	def get_call_address(self, func_call:SExpr) -> int:
		if func_call.is_function():
			return func_call.func_addr

		if (vuc := func_call.var_use_chain) is None:
			return -1

		if (var_tif := self.state.get_var(vuc.var)) is utils.UNKNOWN_TYPE:
			return -1

		member = vuc.transform_type(var_tif)
		if isinstance(member, utils.ShiftedStruct):
			addr = utils.str2addr(member.comment)
			if addr == -1:
				addr = utils.str2addr(member.name)
		else:
			addr = -1
			utils.log_warn(f"failed to get final member from {var_tif} {vuc}")

		return addr

	def is_var_possible_ptr(self, var:Var, var_uses:TFG) -> bool:
		for node in var_uses.iterate_nodes():
			for vuc in node.sexpr.extract_var_use_chains():
				if vuc.var != var:
					continue
				if not vuc.is_possible_ptr():
					return False
		return True