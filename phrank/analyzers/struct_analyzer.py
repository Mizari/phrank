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
		self.analyzed_functions = set()
		self.vtable_analyzer = VtableAnalyzer(func_factory)

	def add_type_uses(self, var_uses:VarUses, var_type:idaapi.tinfo_t):
		for var_write in var_uses.writes:
			if var_write.is_assign(): continue
			write_type = self.get_write_type(var_write)
			self.add_type_use(var_type, var_write, write_type)

		for var_read in var_uses.reads:
			self.add_type_use(var_type, var_read, utils.UNKNOWN_TYPE)

		for cast in var_uses.casts:
			# FIXME kostyl
			if cast.is_var_arg():
				continue
			cast_type = self.get_cast_type(cast)

			tif = cast.transform_type(var_type)
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

			print("WARNING:", f"cant cast {str(var_type)} transformed by {cast.uses_str()} into {str(tif)} to {str(cast_type)}")

	def add_type_use(self, var_type:idaapi.tinfo_t, vuc:VarUseChain, member_type:idaapi.tinfo_t):
		tif = vuc.transform_type(var_type)
		if isinstance(tif, utils.ShiftedStruct):
			self.add_member_type(tif.strucid, tif.offset, member_type)
			return

		# kostyl for UNKNOWN member pointer
		if var_type.is_ptr() and (ptif := var_type.get_pointed_object()).is_struct() and (offset := vuc.get_ptr_offset()) is not None:
			strucid = utils.tif2strucid(ptif)
			self.add_member_type(strucid, offset, member_type)
			return

		print("WARNING:", f"cant add member={str(member_type)} to type={str(var_type)} transformed by {vuc.uses_str()}")

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
				print(
					"WARNING: failed to change type of",
					lvar_struct.name, "at", hex(offset),
					"to", str(member_type),
					"because it overwrites next field at",
					hex(next_offset), "skipping member type change",
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
				if func_call.is_explicit(): continue

				frm = func_call.call_expr.ea
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
			var_uses.casts += va.casts
		return var_uses

	def get_var_call_casts(self, var:Var) -> list[CallCast]:
		casts = []
		for func_ea in var.get_functions():
			aa = self.get_ast_analysis(func_ea)
			va = aa.get_var_uses(var)
			casts += va.casts
		return casts

	def get_write_type(self, var_write:VarWrite) -> idaapi.tinfo_t:
		return self.analyze_cexpr(var_write.func_ea, var_write.value)

	def get_cast_type(self, call_cast:CallCast) -> idaapi.tinfo_t:
		address = self.get_call_address(call_cast.func_call)
		if address == -1:
			return utils.UNKNOWN_TYPE

		return self.analyze_var(Var(address, call_cast.arg_id))

	def analyze_cexpr(self, func_ea:int, cexpr:idaapi.cexpr_t) -> idaapi.tinfo_t:
		cexpr = utils.strip_casts(cexpr)

		if cexpr.op == idaapi.cot_var:
			return self.analyze_var(Var(func_ea, cexpr.v.idx))

		if cexpr.op == idaapi.cot_call and cexpr.x.op == idaapi.cot_obj and utils.is_func_start(cexpr.x.obj_ea):
			call_ea = cexpr.x.obj_ea
			return self.analyze_retval(call_ea)

		if cexpr.op in {idaapi.cot_num}:
			return cexpr.type

		if cexpr.op == idaapi.cot_obj and not utils.is_func_start(cexpr.obj_ea):
			gvar_type = self.analyze_var(Var(cexpr.obj_ea))
			if gvar_type is utils.UNKNOWN_TYPE:
				return utils.UNKNOWN_TYPE

			actual_type = utils.addr2tif(cexpr.obj_ea)
			if actual_type is None or actual_type.is_array():
				gvar_ptr_type = idaapi.tinfo_t()
				gvar_ptr_type.create_ptr(gvar_type)
				gvar_type = gvar_ptr_type
			return gvar_type

		if cexpr.op == idaapi.cot_ref and cexpr.x.op == idaapi.cot_obj and not utils.is_func_start(cexpr.x.obj_ea):
			gvar_type = self.analyze_var(Var(cexpr.x.obj_ea))
			if gvar_type is utils.UNKNOWN_TYPE:
				return utils.UNKNOWN_TYPE

			gvar_ptr_type = idaapi.tinfo_t()
			gvar_ptr_type.create_ptr(gvar_type)
			return gvar_ptr_type

		print("WARNING:", "unknown cexpr value", cexpr.opname)
		return utils.UNKNOWN_TYPE

	def calculate_var_type_by_uses(self, var_uses: VarUses):
		if len(var_uses) == 0:
			return utils.UNKNOWN_TYPE

		casts = var_uses.casts
		reads = var_uses.reads
		writes = [w for w in var_uses.writes if not w.is_assign()]
		assigns = [w for w in var_uses.writes if w.is_assign()]

		assigns_types = [self.get_write_type(t) for t in assigns]
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
			if not w.is_possible_ptr():
				print("non-pointer writes are not supported for now", w)
				return utils.UNKNOWN_TYPE

		# weeding out non-pointers2
		for c in casts:
			if c.is_possible_ptr() is None:
				print("non-pointer casts are not supported for now", c)
				return utils.UNKNOWN_TYPE

		# weeding out non-pointers3
		for r in reads:
			if not r.is_possible_ptr():
				print("non-pointer reads are not supported for now", r)
				return utils.UNKNOWN_TYPE

		writes_types = [self.get_write_type(w) for w in writes]

		# single write at offset 0 does not create new type
		if len(var_uses) == 1 and len(writes) == 1 and writes[0].get_ptr_offset() == 0:
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
				arg_type = arg_type.get_pointed_object()

			# checking that writes do not go outside of casted value
			cast_end = arg_type.get_size()
			for i, w in enumerate(writes):
				write_start = w.get_ptr_offset()
				if write_start is None:
					continue
				write_end = writes_types[i].get_size()
				# write_start, write_end = w[0], w[1].get_size()
				if write_start < 0 or write_end > cast_end:
					return utils.UNKNOWN_TYPE

			arg_type.create_ptr(arg_type)
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

		var_uses = self.get_var_uses(var)
		if len(var_uses) == 0:
			print("WARNING:", f"found no var uses for {str(var)}")
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

		aa = self.get_ast_analysis(func_ea)
		r_types = []
		for r in aa.returns:
			var_type = self.analyze_var(r.var)
			if var_type is utils.UNKNOWN_TYPE:
				r_types.append(utils.UNKNOWN_TYPE)
				continue

			r_type = r.transform_type(var_type)
			if r_type is utils.UNKNOWN_TYPE:
				print("WARNING: failed to analyze retval chain", utils.expr2str(r.retval))
			r_types.append(r_type)

		if len(r_types) == 1:
			retval_type = r_types[0]
		elif len(r_types) == 0:
			retval_type = utils.UNKNOWN_TYPE
		else:
			rv0 = r_types[0]
			for i in range(1, len(r_types)):
				if r_types[i] != rv0:
					print(
						"WARNING: multiple retval types are not supported",
						hex(func_ea), idaapi.get_name(func_ea)
					)
					retval_type = utils.UNKNOWN_TYPE
					break
			else:
				retval_type = rv0

		self.retval2tinfo[func_ea] = retval_type
		return retval_type

	def analyze_function(self, func_ea:int):
		if func_ea in self.analyzed_functions:
			return
		self.analyzed_functions.add(func_ea)

		for call_from_ea in utils.get_func_calls_from(func_ea):
			self.analyze_function(call_from_ea)

		for i in range(self.get_lvars_counter(func_ea)):
			self.analyze_var(Var(func_ea, i))

		self.analyze_retval(func_ea)

	def get_call_address(self, func_call:FuncCall) -> int:
		if func_call.is_explicit():
			return func_call.address

		vuc = func_call.implicit_var_use_chain
		if vuc is None:
			return -1

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
			print("WARNING:", f"failed to get final member from {var_tif} {str(vuc)}")

		if addr == -1:
			print("WARNING: unknown implicit call", utils.expr2str(func_call.call_expr, hide_casts=True))
		return addr

	def propagate_var(self, var:Var):
		var_type = self.get_var_type(var)
		if utils.tif2strucid(var_type) not in self.new_types:
			return

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
			current_type = self.var2tinfo.get(arg_var, utils.UNKNOWN_TYPE)
			if current_type is utils.UNKNOWN_TYPE:
				lvar_uses = self.get_var_uses(arg_var)
				arg_assigns = [w for w in lvar_uses.writes if w.is_assign()]
				if len(arg_assigns) != 0:
					continue

				self.var2tinfo[arg_var] = var_type
				self.propagate_var(arg_var)
				self.add_type_uses(lvar_uses, var_type)
				continue

			if current_type != var_type:
				print(
					"Failed to propagate", str(var_type),
					"to", self.get_lvar_name(call_ea, call_cast.arg_id),
					"in", idaapi.get_name(call_ea),
					"because variable has different type", current_type,
				)