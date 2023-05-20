from __future__ import annotations

import idaapi

import phrank.utils as utils

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.analyzers.vtable_analyzer import VtableAnalyzer
from phrank.containers.structure import Structure
from phrank.ast_parts import *


class StructAnalyzer(TypeAnalyzer):
	def __init__(self, func_factory=None) -> None:
		super().__init__(func_factory)
		self.vtable_analyzer = VtableAnalyzer(func_factory)

	def add_type_uses(self, var_uses:VarUses, var_type:idaapi.tinfo_t):
		for var_write in var_uses.writes:
			if var_write.is_assign(): continue

			write_type = self.analyze_sexpr_type(var_write.value)
			target = self.analyze_target(var_type, var_write.target)
			if target is None:
				utils.log_warn(f"cant add member={str(write_type)} to type={str(var_type)} from write {str(var_write)}")
				continue
			self.add_member_type(target.strucid, target.offset, write_type)

			if var_write.value.is_function():
				addr = var_write.value.function
				self.add_member_name(target.strucid, target.offset, idaapi.get_name(addr))

		for var_read in var_uses.reads:
			target = self.analyze_target(var_type, var_read)
			if target is None:
				utils.log_warn(f"cant read type={str(var_type)} from expr {var_read}")
				continue
			self.add_member_type(target.strucid, target.offset, utils.UNKNOWN_TYPE)

		for cast in var_uses.type_casts:
			if cast.arg.var_use_chain is None: continue
			cast_arg = cast.arg.var_use_chain

			# FIXME kostyl
			if cast_arg.is_var_chain():
				continue
			cast_type = cast.tif

			tif = cast_arg.transform_type(var_type)
			if isinstance(tif, utils.ShiftedStruct):
				self.add_member_type(tif.strucid, tif.offset, cast_type)
				continue

			base, offset = utils.get_shifted_base(tif)
			if base is not None and utils.is_struct_ptr(base):
				strucid = utils.tif2strucid(base)
				if cast_type is utils.UNKNOWN_TYPE:
					self.add_member_type(strucid, offset, cast_type)
					continue
				elif cast_type.is_ptr():
					self.add_member_type(strucid, offset, cast_type.get_pointed_object())
					continue
				elif cast_type.is_array():
					self.add_member_type(strucid, offset, cast_type)
					continue

			utils.log_warn(f"cant cast {str(var_type)} transformed by {str(cast_arg)} into {str(tif)} to {str(cast_type)}")

		for cast in var_uses.call_casts:
			if cast.arg.var_use_chain is None: continue
			cast_arg = cast.arg.var_use_chain

			# FIXME kostyl
			if cast_arg.is_var_chain():
				continue
			cast_type = self.get_cast_type(cast)

			tif = cast_arg.transform_type(var_type)
			if isinstance(tif, utils.ShiftedStruct):
				self.add_member_type(tif.strucid, tif.offset, cast_type)
				continue

			base, offset = utils.get_shifted_base(tif)
			if base is not None and utils.is_struct_ptr(base):
				strucid = utils.tif2strucid(base)
				if cast_type is utils.UNKNOWN_TYPE:
					self.add_member_type(strucid, offset, cast_type)
					continue
				elif cast_type.is_ptr():
					self.add_member_type(strucid, offset, cast_type.get_pointed_object())
					continue

			utils.log_warn(f"cant cast {str(var_type)} transformed by {str(cast_arg)} into {str(tif)} to {str(cast_type)}")

	def analyze_target(self, var_type:idaapi.tinfo_t, sexpr:SExpr) -> utils.ShiftedStruct|None:
		if sexpr.var_use_chain is None:
			return None
		vuc = sexpr.var_use_chain

		tif = vuc.transform_type(var_type)
		if isinstance(tif, utils.ShiftedStruct):
			return tif

		# kostyl for UNKNOWN member pointer
		if var_type.is_ptr() and (ptif := var_type.get_pointed_object()).is_struct() and (offset := vuc.get_ptr_offset()) is not None:
			strucid = utils.tif2strucid(ptif)
			if strucid == -1:
				return None
			return utils.ShiftedStruct(strucid, offset)
		return None

	def add_member_type(self, strucid:int, offset:int, member_type:idaapi.tinfo_t):
		# rogue shifted struct
		if offset < 0:
			return

		# do not modificate existing types
		if strucid not in self.new_types:
			return

		lvar_struct = Structure(strucid)

		# use of the member exists, thus there should be the field
		if not lvar_struct.member_exists(offset):
			lvar_struct.add_member(offset)

		# if unknown, then simply creating new member is enough
		if member_type is utils.UNKNOWN_TYPE:
			return

		next_offset = lvar_struct.get_next_member_offset(offset)
		if next_offset != -1 and offset + member_type.get_size() > next_offset:
			# TODO remove when struct sizes are remembered
			# currently struct size is set by adding 1byte int at the end
			# if that is the case, then allow member type setting
			if lvar_struct.get_member_size(next_offset) != 1 or lvar_struct.size != next_offset + 1:
				utils.log_warn(
					f"failed to change type of "\
					f"{lvar_struct.name} at {hex(offset)} "\
					f"to {str(member_type)} "\
					f"because it overwrites next field at "\
					f"{hex(next_offset)} skipping member type change"
				)
				return

		member_offset = lvar_struct.get_member_start(offset)
		current_type = lvar_struct.get_member_type(offset)
		if  current_type is not None and \
			current_type.is_struct() and \
			current_type.get_size() > member_type.get_size():

			strucid = utils.tif2strucid(current_type)
			self.add_member_type(strucid, offset - member_offset, member_type)
		else:
			lvar_struct.set_member_type(offset, member_type)

	def add_member_name(self, strucid:int, offset:int, name:str):
		# rogue shifted struct
		if offset < 0:
			return

		# do not modificate existing types
		if strucid not in self.new_types:
			return

		lvar_struct = Structure(strucid)

		# use of the member exists, thus there should be the field
		if not lvar_struct.member_exists(offset):
			lvar_struct.add_member(offset)

		lvar_struct.set_member_name(offset, name)

	def apply_analysis(self):
		var_to_propagate = [v for v in self.var2tinfo.keys()]
		for var in var_to_propagate:
			self.propagate_var(var) # modifies var2tinfo

		touched_functions = set()
		for var in self.var2tinfo.keys():
			touched_functions.update(var.get_functions())

		for func_ea in touched_functions:
			func_aa = self.get_ast_analysis(func_ea)
			for func_call in func_aa.calls:
				if not func_call.is_var_use_chain(): continue

				frm = func_call.expr_ea
				if frm == idaapi.BADADDR:
					continue

				call_ea = self.get_call_address(func_call)
				if call_ea == -1:
					continue

				self.new_xrefs.append((frm, call_ea))

		super().apply_analysis()
		self.vtable_analyzer.apply_analysis()

	def clear_analysis(self):
		super().clear_analysis()
		self.vtable_analyzer.clear_analysis()

	def get_var_uses(self, var:Var) -> VarUses:
		var_uses = VarUses()
		for func_ea in var.get_functions():
			aa = self.get_ast_analysis(func_ea)
			va = aa.get_var_uses(var)
			var_uses.writes += va.writes
			var_uses.reads += va.reads
			var_uses.call_casts += va.call_casts
			var_uses.type_casts += va.type_casts
		return var_uses

	def get_var_call_casts(self, var:Var) -> list[CallCast]:
		casts = []
		for func_ea in var.get_functions():
			aa = self.get_ast_analysis(func_ea)
			va = aa.get_var_uses(var)
			casts += va.call_casts
		return casts

	def get_cast_type(self, call_cast:CallCast) -> idaapi.tinfo_t:
		address = self.get_call_address(call_cast.func_call)
		if address == -1:
			return utils.UNKNOWN_TYPE

		return self.analyze_var(Var(address, call_cast.arg_id))

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

	def calculate_var_type_by_uses(self, var_uses: VarUses):
		if len(var_uses) == 0:
			return utils.UNKNOWN_TYPE

		casts = var_uses.call_casts
		reads = var_uses.reads
		writes = [w for w in var_uses.writes if not w.is_assign()]
		assigns = [w for w in var_uses.writes if w.is_assign()]

		assigns_types = [self.analyze_sexpr_type(t.value) for t in assigns]
		# single assign can only be one type
		if len(assigns) == 1:
			return assigns_types[0]

		# try to resolve multiple assigns
		if len(assigns) > 1:
			# prefer types over non-types
			strucid_assign_types = []
			for i, asg in enumerate(assigns):
				assign_type = assigns_types[i]
				if assign_type is utils.UNKNOWN_TYPE:
					continue
				strucid = utils.tif2strucid(assign_type)
				if strucid != -1:
					strucid_assign_types.append(assign_type)

			if len(strucid_assign_types) == 1:
				return strucid_assign_types[0]
			# multiple different assignments is unknown
			else:
				return utils.UNKNOWN_TYPE

		# weeding out non-pointers
		for w in writes:
			if w.target.var_use_chain is None: continue
			if not w.target.var_use_chain.is_possible_ptr():
				utils.log_warn("non-pointer writes are not supported for now {w}")
				return utils.UNKNOWN_TYPE

		# weeding out non-pointers2
		for c in casts:
			if c.arg.var_use_chain is None: continue
			if c.arg.var_use_chain.is_possible_ptr() is None:
				utils.log_warn(f"non-pointer casts are not supported for now {c}")
				return utils.UNKNOWN_TYPE

		# weeding out non-pointers3
		for r in reads:
			if r.var_use_chain is None: continue
			if not r.var_use_chain.is_possible_ptr():
				utils.log_warn(f"non-pointer reads are not supported for now {r.op}")
				return utils.UNKNOWN_TYPE

		writes_types = [self.analyze_sexpr_type(w.value) for w in writes]

		# single write at offset 0 does not create new type
		if len(var_uses) == 1 and len(writes) == 1 and writes[0].target.var_use_chain is not None and writes[0].target.var_use_chain.get_ptr_offset() == 0:
			write_type = writes_types[0].copy()
			write_type.create_ptr(write_type)
			return write_type

		# single cast at offset 0 might be existing type
		if len(casts) == 1 and casts[0].is_var_arg():
			arg_type = self.get_cast_type(casts[0])

			# casting to something unknown yield unknown
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
					if w.target.var_use_chain is None: continue
					write_start = w.target.var_use_chain.get_ptr_offset()
					if write_start is None: continue

					write_end = writes_types[i].get_size()
					if write_end == idaapi.BADSIZE and writes_types[i] is not utils.UNKNOWN_TYPE:
						utils.log_warn(f"failed to calculate write size of {str(writes_types[i])}")
						continue

					# found write outside of cast, new struct then
					if write_start < 0 or write_end > arg_size:
						lvar_struct = Structure.create()
						self.new_types.add(lvar_struct.strucid)
						lvar_tinfo = lvar_struct.ptr_tinfo
						return lvar_tinfo
				return arg_type

		# TODO writes into array of one type casts, that start at offset 0
		# TODO check if all writes are to the same offset
		# TODO check if all writes are actually array writes at various offsets

		# all cases ended, assuming new structure pointer
		lvar_struct = Structure.create()
		self.new_types.add(lvar_struct.strucid)
		lvar_tinfo = lvar_struct.ptr_tinfo
		return lvar_tinfo

	def get_original_var_type(self, var:Var) -> idaapi.tinfo_t:
		if var.is_local():
			return self.get_cfunc_lvar_type(var.func_ea, var.lvar_id)
		else:
			return utils.addr2tif(var.obj_ea)

	def set_var_type(self, var:Var, var_tinfo:idaapi.tinfo_t):
		self.var2tinfo[var] = var_tinfo

	def get_var_type(self, var:Var) -> idaapi.tinfo_t:
		return self.var2tinfo.get(var, utils.UNKNOWN_TYPE)

	def analyze_var(self, var:Var) -> idaapi.tinfo_t:
		current_lvar_tinfo = self.var2tinfo.get(var)
		if current_lvar_tinfo is not None:
			return current_lvar_tinfo

		original_var_tinfo = self.get_original_var_type(var)
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

		else:
			vtbl = self.vtable_analyzer.analyze_var(var)
			if vtbl is not utils.UNKNOWN_TYPE:
				return vtbl

		self.var2tinfo[var] = utils.UNKNOWN_TYPE # to break recursion

		var_uses = self.get_var_uses(var)
		if len(var_uses) == 0:
			utils.log_warn(f"found no var uses for {str(var)}")
			self.var2tinfo[var] = utils.UNKNOWN_TYPE
			return utils.UNKNOWN_TYPE

		# TODO check that var is not recursively dependant on itself
		# TODO check that var uses are compatible
		var_tinfo = self.calculate_var_type_by_uses(var_uses)
		if utils.tif2strucid(var_tinfo) != -1:
			self.add_type_uses(var_uses, var_tinfo)
		self.var2tinfo[var] = var_tinfo
		return var_tinfo

	def analyze_retval(self, func_ea:int) -> idaapi.tinfo_t:
		rv = self.retval2tinfo.get(func_ea)
		if rv is not None:
			return rv
		self.retval2tinfo[func_ea] = utils.UNKNOWN_TYPE # to break recursion

		aa = self.get_ast_analysis(func_ea)
		r_types = [self.analyze_sexpr_type(r) for r in aa.returns]

		if len(r_types) == 1:
			retval_type = r_types[0]
		elif len(r_types) == 0:
			retval_type = utils.UNKNOWN_TYPE
		else:
			rv0 = r_types[0]
			for i in range(1, len(r_types)):
				if r_types[i] != rv0:
					utils.log_warn(
						f"multiple retval types are not supported "\
						f"{hex(func_ea)} {idaapi.get_name(func_ea)}"
					)
					retval_type = utils.UNKNOWN_TYPE
					break
			else:
				retval_type = rv0

		self.retval2tinfo[func_ea] = retval_type
		return retval_type

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
			utils.log_warn(f"failed to get final member from {var_tif} {str(vuc)}")

		return addr

	def propagate_var(self, var:Var):
		var_type = self.get_var_type(var)
		if utils.tif2strucid(var_type) == -1:
			return

		for func_ea in var.get_functions():
			aa = self.get_ast_analysis(func_ea)
			for asg in aa.var_writes:
				if not asg.value.is_var(var): continue
				if (target_var := asg.target.var) is None: continue
				self.propagate_type_to_var(target_var, var_type)

		casts = self.get_var_call_casts(var)
		for call_cast in casts:
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
			arg_assigns = [w for w in lvar_uses.writes if w.is_assign()]
			if len(arg_assigns) != 0:
				return

			self.var2tinfo[var] = new_type
			self.propagate_var(var)
			self.add_type_uses(lvar_uses, new_type)
			return

		if current_type != new_type:
			utils.log_warn(
				f"failed to propagate {str(new_type)} "\
				f"to {str(var)} "\
				f"because variable has different type {current_type}"
			)