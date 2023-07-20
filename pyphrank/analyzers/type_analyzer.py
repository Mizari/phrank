from __future__ import annotations

import idc
import idaapi

from pyphrank.function_manager import FunctionManager
from pyphrank.ast_parts import Var, SExpr, VarUseChain, Node, UNKNOWN_SEXPR, NOP_NODE
from pyphrank.containers.structure import Structure
from pyphrank.ast_analyzer import ASTAnalysis, chain_nodes
from pyphrank.containers.vtable import Vtable
from pyphrank.container_manager import ContainerManager
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
	for tif in tifs:
		if tif is utils.UNKNOWN_TYPE:
			continue

		strucid = utils.tif2strucid(tif)
		if strucid != -1:
			strucid_assign_types.append(tif)

	if len(strucid_assign_types) == 1:
		return strucid_assign_types[0]

	# multiple different assignments is unknown
	else:
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

def shrink_ast_analysis(aa:ASTAnalysis) -> ASTAnalysis:
	def remove_node(node:Node):
		for parent in node.parents:
			parent.children.remove(node)
		for child in node.children:
			child.parents.remove(node)
		for parent in node.parents:
			for child in node.children:
				parent.children.append(child)
				child.parents.append(parent)

	new_aa = aa.copy()
	bad_nodes = {n for n in new_aa.iterate_nodes() if not is_typeful_node(n)}
	for node in bad_nodes:
		remove_node(node)
	return new_aa


class TypeAnalyzer(FunctionManager):
	def __init__(self, cfunc_factory=None, ast_analyzer=None) -> None:
		super().__init__(cfunc_factory=cfunc_factory, ast_analyzer=ast_analyzer)
		self.container_manager = ContainerManager()
		self.ast_analysis_cache : dict[int,ASTAnalysis ]= {}

		self.var2tinfo : dict[Var, idaapi.tinfo_t] = {}
		self.retval2tinfo : dict[int, idaapi.tinfo_t] = {}

	def cache_analysis(self, analysis:ASTAnalysis):
		self.ast_analysis_cache[analysis.actx.addr] = analysis

	def get_ast_analysis(self, func_ea:int) -> ASTAnalysis:
		cached = self.ast_analysis_cache.get(func_ea)
		if cached is not None:
			return cached

		aa = super().get_ast_analysis(func_ea)
		shrinked_aa = shrink_ast_analysis(aa)
		self.ast_analysis_cache[func_ea] = shrinked_aa
		return shrinked_aa

	def get_db_var_type(self, var:Var) -> idaapi.tinfo_t:
		if var.is_local():
			return self.get_cfunc_lvar_type(var.func_ea, var.lvar_id)
		else:
			return utils.addr2tif(var.obj_ea)

	def set_db_var_type(self, var:Var, var_type:idaapi.tinfo_t):
		if var.is_local():
			self.set_lvar_tinfo(var.func_ea, var.lvar_id, var_type)
		else:
			rv = idc.SetType(var.obj_ea, str(var_type) + ';')
			if rv == 0:
				utils.log_warn(f"setting {hex(var.obj_ea)} to {var_type} failed")

	def set_var_type(self, var:Var, var_tinfo:idaapi.tinfo_t):
		self.var2tinfo[var] = var_tinfo

	def get_var_type(self, var:Var) -> idaapi.tinfo_t:
		return self.var2tinfo.get(var, utils.UNKNOWN_TYPE)

	def skip_analysis(self):
		# delete new temporarily created types
		self.container_manager.delete_containers()

		self.var2tinfo.clear()
		self.retval2tinfo.clear()

	def apply_analysis(self):
		var_to_propagate = [v for v in self.var2tinfo.keys()]
		for var in var_to_propagate:
			self.propagate_var(var) # modifies var2tinfo

		touched_functions = set()
		for var in self.var2tinfo.keys():
			touched_functions.update(var.get_functions())

		new_xrefs = []
		for func_ea in touched_functions:
			func_aa = self.get_ast_analysis(func_ea)
			for func_call in func_aa.iterate_implicit_calls():
				if not func_call.is_var_use_chain():
					continue

				frm = func_call.expr_ea
				if frm == idaapi.BADADDR:
					continue

				call_ea = self.get_call_address(func_call)
				if call_ea == -1:
					continue

				new_xrefs.append((frm, call_ea))

		for frm, to in new_xrefs:
			rv = idaapi.add_cref(frm, to, idaapi.fl_CN)
			if not rv:
				utils.log_warn(f"failed to add code reference from {hex(frm)} to {hex(to)}")

		for var, new_type_tif in self.var2tinfo.items():
			if new_type_tif is utils.UNKNOWN_TYPE:
				continue

			self.set_db_var_type(var, new_type_tif)

		self.var2tinfo.clear()
		self.retval2tinfo.clear()
		# new types are already created, simply skip them without deleting
		self.container_manager.clear()

	def analyze_var(self, var:Var) -> idaapi.tinfo_t:
		current_lvar_tinfo = self.var2tinfo.get(var)
		if current_lvar_tinfo is not None:
			return current_lvar_tinfo

		var_tinfo = self.analyze_by_heuristics(var)
		if var_tinfo is not utils.UNKNOWN_TYPE:
			self.var2tinfo[var] = var_tinfo
			return var_tinfo

		self.var2tinfo[var] = utils.UNKNOWN_TYPE # to break recursion
		var_tinfo = self.analyze_by_var_uses(var)
		self.var2tinfo[var] = var_tinfo
		return var_tinfo

	def analyze_retval(self, func_ea:int) -> idaapi.tinfo_t:
		rv = self.retval2tinfo.get(func_ea)
		if rv is not None:
			return rv
		self.retval2tinfo[func_ea] = utils.UNKNOWN_TYPE # to break recursion

		aa = self.get_ast_analysis(func_ea)
		r_types = [self.analyze_sexpr_type(r) for r in aa.iterate_return_sexprs()]
		retval_type = select_type(*r_types)
		self.retval2tinfo[func_ea] = retval_type
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
			return self.get_func_tinfo(sexpr.func_addr)

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
		var_type = self.get_var_type(var)
		if utils.tif2strucid(var_type) == -1:
			return

		var_uses = self.get_all_var_uses(var)
		for target in var_uses.iterate_moves_from():
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
		current_type = self.var2tinfo.get(var, utils.UNKNOWN_TYPE)
		if current_type is utils.UNKNOWN_TYPE:
			lvar_uses = self.get_all_var_uses(var)
			self.var2tinfo[var] = new_type
			self.propagate_var(var)
			self.add_type_uses(lvar_uses, new_type)
			return

		if current_type != new_type:
			utils.log_warn(
				f"failed to propagate {new_type} "\
				f"to {var} "\
				f"because variable has different type {current_type}"
			)

	def get_func_var_uses(self, func_ea:int, var:Var) -> ASTAnalysis:
		aa = self.get_ast_analysis(func_ea)
		nodes = []
		for node in aa.iterate_assign_nodes():
			node = node.copy()
			asg = node.sexpr
			if asg.target.is_var(var):
				nodes.append(node)
			elif asg.target.is_var_use(var):
				nodes.append(node)
			if asg.value.is_var(var):
				nodes.append(node)

		for node in aa.iterate_call_cast_nodes():
			node = node.copy()
			if node.sexpr.is_var_use(var):
				nodes.append(node)
		for node in aa.iterate_type_cast_nodes():
			node = node.copy()
			if node.sexpr.is_var_use(var):
				nodes.append(node)
		for r in aa.iterate_var_reads():
			if r.is_var_use(var) and r.var is None:
				node = Node(Node.EXPR, r)
				nodes.append(node)
		chain_nodes(*nodes)
		if len(nodes) == 0:
			return ASTAnalysis(NOP_NODE.copy(), aa.actx)
		return ASTAnalysis(nodes[0], aa.actx)

	def get_all_var_uses(self, var:Var) -> ASTAnalysis:
		new_entry = NOP_NODE.copy()
		for func_ea in var.get_functions():
			va = self.get_func_var_uses(func_ea, var)
			new_entry.children.append(va.entry)
			va.entry.parents.append(new_entry)
		return ASTAnalysis(new_entry, None)

	def analyze_by_heuristics(self, var:Var) -> idaapi.tinfo_t:
		original_var_tinfo = self.get_db_var_type(var)
		if utils.tif2strucid(original_var_tinfo) != -1:
			# TODO check correctness of writes, read, casts
			return original_var_tinfo

		# local/global specific analysis
		if var.is_local():
			cfunc_lvar = self.get_cfunc_lvar(var.func_ea, var.lvar_id)
			if cfunc_lvar is not None and cfunc_lvar.is_stk_var() and not cfunc_lvar.is_arg_var:
				return utils.UNKNOWN_TYPE

			if utils.is_func_import(var.func_ea):
				return original_var_tinfo

		# global var is vtbl
		elif (vtbl := Vtable.from_data(var.obj_ea)) is not None:
			self.container_manager.add_struct(vtbl)
			return vtbl.tinfo
		return utils.UNKNOWN_TYPE

	def analyze_by_var_uses(self, var:Var) -> idaapi.tinfo_t:
		var_uses = self.get_all_var_uses(var)
		if var_uses.total_len() == 0:
			utils.log_warn(f"found no var uses for {var}")
			return utils.UNKNOWN_TYPE

		moves_types = []
		for m in var_uses.iterate_moves_to():
			mtype = self.analyze_sexpr_type(m)
			if mtype not in moves_types:
				moves_types.append(mtype)
		if len(moves_types) != 0 and (var_tinfo := select_type(*moves_types)) is not utils.UNKNOWN_TYPE:
			return var_tinfo

		if not self.is_ptr(var_uses):
			return utils.UNKNOWN_TYPE

		"""
		write_assigns = [a for a in var_uses.iterate_assign_sexprs() if is_assign_write(a)]
		writes = [w for w in var_uses.iterate_writes()]
		reads = [r for r in var_uses.iterate_var_reads()]
		type_casts = [c for c in var_uses.iterate_type_cast_sexprs()]
		call_casts = []
		for c in var_uses.iterate_call_cast_nodes():
			if (addr := self.get_call_address(c.func_call)) == -1:
				call_casts.append(c)
				continue

			arg_var = Var(addr, c.arg_id)
			if (arg_type := self.var2tinfo.get(arg_var)) is None:
				call_casts.append(c)
				continue

			type_casts.append(Node(Node.TYPE_CAST, c, arg_type))

		type_uses = VarUses()
		type_uses.assigns = write_assigns
		type_uses.reads = reads
		type_uses.type_casts = type_casts
		type_uses.call_casts = call_casts
		"""
		type_uses = var_uses

		rw_ptr_uses = set()
		max_ptr_offset = 0
		for w in var_uses.iterate_writes():
			vuc = w.target
			write_offset = vuc.get_ptr_offset()
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
		for r in var_uses.iterate_var_reads():
			read_offset = r.var_use_chain.get_ptr_offset()
			rw_ptr_uses.add(read_offset)
			max_ptr_offset = max(max_ptr_offset, read_offset)
		rw_ptr_uses.discard(None) # get_ptr_offset can return None

		if type_uses.casts_len() == 0:
			# cant determine ptr use without writes to it
			if len([w for w in type_uses.iterate_writes()]) == 0:
				return utils.UNKNOWN_TYPE

			# ptr uses other than offset0 create new type
			if rw_ptr_uses != {0}:
				lvar_struct = Structure.new()
				self.container_manager.add_struct(lvar_struct)
				type_tif = lvar_struct.ptr_tinfo
				self.add_type_uses(type_uses, type_tif)
				return type_tif

			write_types = [self.analyze_sexpr_type(w.value) for w in var_uses.iterate_writes()]
			write_type = select_type(*write_types)
			if write_type is utils.UNKNOWN_TYPE:
				return utils.UNKNOWN_TYPE
			write_type.create_ptr(write_type)
			return write_type

		if type_uses.casts_len() == 1:
			call_casts = [c for c in type_uses.iterate_call_cast_nodes()]
			type_casts = [c for c in type_uses.iterate_type_cast_nodes()]
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
				lvar_struct = Structure.new()
				self.container_manager.add_struct(lvar_struct)
				type_tif = lvar_struct.ptr_tinfo
				self.add_type_uses(type_uses, type_tif)
				return type_tif

			# if no other uses but single cast
			if type_uses.uses_len() == 1:
				return arg_type

			# single cast and writes into casted type
			if arg_type.is_ptr():
				arg_size = arg_type.get_pointed_object().get_size()
			else:
				arg_size = arg_type.get_size()

			if arg_size == idaapi.BADSIZE:
				utils.log_warn(f"failed to calculate size of argument {str(arg_type)} for {str(var)}")
				return utils.UNKNOWN_TYPE

			# have use outside of type => new type
			if max_ptr_offset > arg_size:
				lvar_struct = Structure.new()
				self.container_manager.add_struct(lvar_struct)
				type_tif = lvar_struct.ptr_tinfo
				self.add_type_uses(type_uses, type_tif)
				return type_tif

			# otherwise not new type
			# TODO check incompatible uses, should create new type if found
			else:
				self.add_type_uses(type_uses, arg_type)
				return arg_type

		lvar_struct = Structure.new()
		self.container_manager.add_struct(lvar_struct)
		type_tif = lvar_struct.ptr_tinfo
		self.add_type_uses(type_uses, type_tif)
		return type_tif

	def add_type_uses(self, var_uses:ASTAnalysis, var_type:idaapi.tinfo_t):
		for var_write in var_uses.iterate_writes():
			write_type = self.analyze_sexpr_type(var_write.value)
			target = self.analyze_target(var_type, var_write.target)
			if target is None:
				utils.log_warn(f"cant add member={write_type} to type={var_type} from write {var_write}")
				continue
			self.container_manager.add_member_type(target.strucid, target.offset, write_type)

			if var_write.value.is_function():
				addr = var_write.value.function
				self.container_manager.add_member_name(target.strucid, target.offset, idaapi.get_name(addr))

		for var_read in var_uses.iterate_var_reads():
			target = self.analyze_target(var_type, var_read.var_use_chain)
			if target is None:
				utils.log_warn(f"cant read type={var_type} from expr {var_read}")
				continue
			self.container_manager.add_member_type(target.strucid, target.offset, utils.UNKNOWN_TYPE)

		for node in var_uses.iterate_type_cast_nodes():
			type_cast = node.sexpr
			if type_cast.var_use_chain is None:
				continue
			cast_arg = type_cast.var_use_chain

			# FIXME kostyl
			if cast_arg.is_var_chain():
				continue
			self.add_type_cast(cast_arg, node.tif, var_type)

		for call_cast in var_uses.iterate_call_cast_sexprs():
			cast_arg = call_cast.var_use_chain
			if cast_arg is None:
				continue
			# TODO
			if cast_arg.is_var_chain():
				continue
			cast_type = self.analyze_call_cast_type(call_cast)
			self.add_type_cast(cast_arg, cast_type, var_type)

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

	def analyze_call_cast_type(self, call_cast:SExpr) -> idaapi.tinfo_t:
		address = self.get_call_address(call_cast)
		if address == -1:
			return utils.UNKNOWN_TYPE

		return self.analyze_var(Var(address, call_cast.arg_id))

	def get_call_address(self, func_call:SExpr) -> int:
		if func_call.is_function():
			return func_call.function

		if func_call.var_use_chain is None:
			return -1
		vuc = func_call.var_use_chain
		var_tif = self.get_var_type(vuc.var)
		if var_tif is utils.UNKNOWN_TYPE:
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

	def is_ptr(self, var_uses:ASTAnalysis) -> bool:
		if var_uses.uses_len() == 0:
			return False

		# weeding out non-pointers
		for w in var_uses.iterate_writes():
			if not w.target.is_possible_ptr():
				utils.log_warn("non-pointer writes are not supported for now {w}")
				return False

		# weeding out non-pointers2
		for c in var_uses.iterate_call_cast_sexprs():
			if c.var_use_chain is None:
				continue
			if c.var_use_chain.is_possible_ptr() is None:
				utils.log_warn(f"non-pointer casts are not supported for now {c}")
				return False

		# weeding out non-pointers3
		for r in var_uses.iterate_var_reads():
			if not r.var_use_chain.is_possible_ptr():
				utils.log_warn(f"non-pointer reads are not supported for now {r}")
				return False

		# all cases ended, assuming new structure pointer
		return True