from __future__ import annotations

import idc
import idaapi

from pyphrank.function_manager import FunctionManager
from pyphrank.ast_parts import Var, SExpr, VarUses, CallCast
from pyphrank.containers.structure import Structure
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


class TypeAnalyzer(FunctionManager):
	def __init__(self, cfunc_factory=None, ast_analyzer=None) -> None:
		super().__init__(cfunc_factory=cfunc_factory, ast_analyzer=ast_analyzer)
		self.container_manager = ContainerManager()

		self.var2tinfo : dict[Var, idaapi.tinfo_t] = {}
		self.retval2tinfo : dict[int, idaapi.tinfo_t] = {}

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
			for func_call in func_aa.calls:
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
			var_tinfo = vtbl.tinfo
			self.container_manager.add_struct(vtbl)
			self.var2tinfo[var] = var_tinfo
			return var_tinfo

		var_tinfo = self.analyze_by_type_uses(var)
		self.var2tinfo[var] = var_tinfo
		return var_tinfo

	def analyze_retval(self, func_ea:int) -> idaapi.tinfo_t:
		rv = self.retval2tinfo.get(func_ea)
		if rv is not None:
			return rv
		self.retval2tinfo[func_ea] = utils.UNKNOWN_TYPE # to break recursion

		aa = self.get_ast_analysis(func_ea)
		r_types = [self.analyze_sexpr_type(r) for r in aa.returns]
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
			return self.get_func_tinfo(sexpr.function)

		elif sexpr.is_explicit_call():
			return self.analyze_retval(sexpr.function)

		elif sexpr.is_implicit_call():
			addr = self.get_call_address(sexpr.x) # type:ignore
			if addr != -1:
				return self.analyze_retval(addr)

			stype = self.analyze_sexpr_type(sexpr.x) # type:ignore
			if stype.is_funcptr():
				pointed_stype = stype.get_pointed_object()
				rettype = pointed_stype.get_rettype()
				return rettype
			if stype.is_func():
				return stype.get_rettype()

		elif sexpr.is_int():
			return sexpr.y

		utils.log_warn(f"unknown sexpr value in {idaapi.get_name(sexpr.func_ea)}")
		return utils.UNKNOWN_TYPE

	def propagate_var(self, var:Var):
		var_type = self.get_var_type(var)
		if utils.tif2strucid(var_type) == -1:
			return

		var_uses = self.get_var_uses(var)
		for target in var_uses.moves_from:
			if (target_var := target.var) is None:
				continue
			self.propagate_type_to_var(target_var, var_type)

		for call_cast in var_uses.call_casts:
			call_ea = self.get_call_address(call_cast.func_call)
			if call_ea == -1:
				continue

			if utils.is_func_import(call_ea):
				continue

			if not call_cast.is_var_arg():
				continue

			arg_var = Var(call_ea, call_cast.arg_id)
			self.propagate_type_to_var(arg_var, var_type)

	def propagate_type_to_var(self, var:Var, new_type:idaapi.tinfo_t):
		current_type = self.var2tinfo.get(var, utils.UNKNOWN_TYPE)
		if current_type is utils.UNKNOWN_TYPE:
			lvar_uses = self.get_var_uses(var)
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

	def get_var_uses(self, var:Var) -> VarUses:
		var_uses = VarUses()
		for func_ea in var.get_functions():
			aa = self.get_ast_analysis(func_ea)
			va = aa.get_var_uses(var)
			var_uses.moves_from += va.moves_from
			var_uses.moves_to += va.moves_to
			var_uses.writes += va.writes
			var_uses.reads += va.reads
			var_uses.call_casts += va.call_casts
			var_uses.type_casts += va.type_casts
		return var_uses

	def analyze_by_type_uses(self, var:Var) -> idaapi.tinfo_t:
		self.var2tinfo[var] = utils.UNKNOWN_TYPE # to break recursion

		var_uses = self.get_var_uses(var)
		if len(var_uses) == 0:
			utils.log_warn(f"found no var uses for {var}")
			return utils.UNKNOWN_TYPE

		# TODO check that var is not recursively dependent on itself
		# TODO check that var uses are compatible
		moves_types = [self.analyze_sexpr_type(asg) for asg in var_uses.moves_to]
		if len(moves_types) != 0 and (var_tinfo := select_type(*moves_types)) is not utils.UNKNOWN_TYPE:
			return var_tinfo

		var_tinfo = self.get_existing_type(var_uses)
		if var_tinfo is not utils.UNKNOWN_TYPE:
			return var_tinfo

		if self.is_strucptr(var_uses):
			lvar_struct = Structure.new()
			self.container_manager.add_struct(lvar_struct)
			var_tinfo = lvar_struct.ptr_tinfo
			self.add_type_uses(var_uses, var_tinfo)
		else:
			var_tinfo = utils.UNKNOWN_TYPE

		return var_tinfo

	def add_type_uses(self, var_uses:VarUses, var_type:idaapi.tinfo_t):
		for var_write in var_uses.writes:
			write_type = self.analyze_sexpr_type(var_write.value)
			target = self.analyze_target(var_type, var_write.target)
			if target is None:
				utils.log_warn(f"cant add member={write_type} to type={var_type} from write {var_write}")
				continue
			self.container_manager.add_member_type(target.strucid, target.offset, write_type)

			if var_write.value.is_function():
				addr = var_write.value.function
				self.container_manager.add_member_name(target.strucid, target.offset, idaapi.get_name(addr))

		for var_read in var_uses.reads:
			target = self.analyze_target(var_type, var_read)
			if target is None:
				utils.log_warn(f"cant read type={var_type} from expr {var_read}")
				continue
			self.container_manager.add_member_type(target.strucid, target.offset, utils.UNKNOWN_TYPE)

		for type_cast in var_uses.type_casts:
			if type_cast.arg.var_use_chain is None:
				continue
			cast_arg = type_cast.arg.var_use_chain

			# FIXME kostyl
			if cast_arg.is_var_chain():
				continue
			cast_type = type_cast.tif

			tif = cast_arg.transform_type(var_type)
			if isinstance(tif, utils.ShiftedStruct):
				self.container_manager.add_member_type(tif.strucid, tif.offset, cast_type)
				continue

			base, offset = utils.get_shifted_base(tif)
			if base is not None and utils.is_struct_ptr(base):
				strucid = utils.tif2strucid(base)
				if cast_type is utils.UNKNOWN_TYPE:
					self.container_manager.add_member_type(strucid, offset, cast_type)
					continue
				elif cast_type.is_ptr():
					self.container_manager.add_member_type(strucid, offset, cast_type.get_pointed_object())
					continue
				elif cast_type.is_array():
					self.container_manager.add_member_type(strucid, offset, cast_type)
					continue

			utils.log_warn(f"cant cast {var_type} transformed by {cast_arg} into {tif} to {cast_type}")

		for call_cast in var_uses.call_casts:
			if call_cast.arg.var_use_chain is None:
				continue
			cast_arg = call_cast.arg.var_use_chain

			# FIXME kostyl
			if cast_arg.is_var_chain():
				continue
			cast_type = self.analyze_call_cast_type(call_cast)

			tif = cast_arg.transform_type(var_type)
			if isinstance(tif, utils.ShiftedStruct):
				self.container_manager.add_member_type(tif.strucid, tif.offset, cast_type)
				continue

			base, offset = utils.get_shifted_base(tif)
			if base is not None and utils.is_struct_ptr(base):
				strucid = utils.tif2strucid(base)
				if cast_type is utils.UNKNOWN_TYPE:
					self.container_manager.add_member_type(strucid, offset, cast_type)
					continue
				elif cast_type.is_ptr():
					self.container_manager.add_member_type(strucid, offset, cast_type.get_pointed_object())
					continue

			utils.log_warn(f"cant cast {var_type} transformed by {cast_arg} into {tif} to {cast_type}")

	def analyze_target(self, var_type:idaapi.tinfo_t, sexpr:SExpr) -> utils.ShiftedStruct|None:
		if sexpr.var_use_chain is None:
			return None
		vuc = sexpr.var_use_chain

		tif = vuc.transform_type(var_type)
		if isinstance(tif, utils.ShiftedStruct):
			return tif

		# kostyl for UNKNOWN member pointer
		if utils.is_struct_ptr(var_type) and (offset := vuc.get_ptr_offset()) is not None:
			strucid = utils.tif2strucid(var_type)
			if strucid == -1:
				return None
			return utils.ShiftedStruct(strucid, offset)
		return None

	def analyze_call_cast_type(self, call_cast:CallCast) -> idaapi.tinfo_t:
		address = self.get_call_address(call_cast.func_call)
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

	def is_strucptr(self, var_uses: VarUses) -> bool:
		if len(var_uses) == 0:
			return False

		# weeding out non-pointers
		for w in var_uses.writes:
			if w.target.var_use_chain is None:
				continue
			if not w.target.var_use_chain.is_possible_ptr():
				utils.log_warn("non-pointer writes are not supported for now {w}")
				return False

		casts = var_uses.call_casts
		# weeding out non-pointers2
		for c in casts:
			if c.arg.var_use_chain is None:
				continue
			if c.arg.var_use_chain.is_possible_ptr() is None:
				utils.log_warn(f"non-pointer casts are not supported for now {c}")
				return False

		reads = var_uses.reads
		# weeding out non-pointers3
		for r in reads:
			if r.var_use_chain is None:
				continue
			if not r.var_use_chain.is_possible_ptr():
				utils.log_warn(f"non-pointer reads are not supported for now {r.op}")
				return False

		# all cases ended, assuming new structure pointer
		return True

	def get_existing_type(self, var_uses:VarUses) -> idaapi.tinfo_t:
		writes = var_uses.writes
		writes_types = [self.analyze_sexpr_type(w.value) for w in writes]

		# single write at offset 0 does not create new type
		if len(var_uses) == 1 and len(writes) == 1 and writes[0].target.var_use_chain is not None and writes[0].target.var_use_chain.get_ptr_offset() == 0:
			write_type = writes_types[0].copy()
			write_type.create_ptr(write_type)
			return write_type

		casts = var_uses.call_casts

		# single cast at offset 0 might be existing type
		if len(casts) == 1 and casts[0].is_var_arg():
			arg_type = self.analyze_call_cast_type(casts[0])

			# casting to something unknown yields unknown
			if arg_type is utils.UNKNOWN_TYPE:
				return utils.UNKNOWN_TYPE

			# simple variable passing does not create new type
			if len(writes) == 0:
				return arg_type

			# single cast and writes into casted type
			if arg_type.is_ptr():
				arg_size = arg_type.get_pointed_object().get_size()
			else:
				arg_size = arg_type.get_size()
			if arg_size == idaapi.BADSIZE and arg_type is not utils.UNKNOWN_TYPE:
				utils.log_warn(f"failed to calculate size of argument {str(arg_type)}")
			else:
				# checking that writes do not go outside of casted value
				for i, w in enumerate(writes):
					if w.target.var_use_chain is None:
						continue
					write_start = w.target.var_use_chain.get_ptr_offset()
					if write_start is None:
						continue

					write_end = writes_types[i].get_size()
					if write_end == idaapi.BADSIZE and writes_types[i] is not utils.UNKNOWN_TYPE:
						utils.log_warn(f"failed to calculate write size of {str(writes_types[i])}")
						continue

					# found write outside of cast, new type then
					if write_start < 0 or write_end > arg_size:
						return utils.UNKNOWN_TYPE
				return arg_type

		# TODO writes into array of one type casts, that start at offset 0
		# TODO check if all writes are to the same offset
		# TODO check if all writes are actually array writes at various offsets

		return utils.UNKNOWN_TYPE
