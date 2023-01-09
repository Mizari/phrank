import idaapi

import phrank.utils as utils

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.analyzers.vtable_analyzer import VtableAnalyzer
from phrank.containers.structure import Structure
from phrank.ast_parts import *


class VarUses:
	def __init__(self):
		self.assigns:list[VarAssign] = []
		self.writes:list[VarWrite]   = []
		self.reads:list[VarRead]     = []
		self.casts:list[CallCast]    = []


class StructAnalyzer(TypeAnalyzer):
	def __init__(self, func_factory=None) -> None:
		super().__init__(func_factory)
		self.analyzed_functions = set()
		self.vtable_analyzer = VtableAnalyzer(func_factory)

	def add_member_type(self, strucid:int, offset:int, member_type:idaapi.tinfo_t):
		# do not modificate existing types
		if strucid not in self.new_types:
			return

		lvar_struct = Structure(strucid)

		# use of the member exists, thus there should be the field
		if not lvar_struct.member_exists(offset):
			lvar_struct.add_member(offset)

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
		current_type = lvar_struct.get_member_tinfo(offset)
		if  current_type is not None and \
			current_type.is_struct() and \
			current_type.get_size() > member_type.get_size():

			strucid = utils.tif2strucid(current_type)
			self.add_member_type(strucid, offset - member_offset, member_type)
		else:
			lvar_struct.set_member_type(offset, member_type)

	def apply_analysis(self):
		lvars_to_propagate = []
		for (func_ea, lvar_id), new_type_tif in self.lvar2tinfo.items():
			if new_type_tif is not utils.UNKNOWN_TYPE:
				lvars_to_propagate.append((func_ea, lvar_id))

		for func_ea, lvar_id in lvars_to_propagate:
			upd = self.propagate_lvar_down(func_ea, lvar_id)
			self.lvar2tinfo.update(upd)

		gvars_to_propagate = []
		for obj_ea, new_type_tif in self.gvar2tinfo.items():
			if new_type_tif is not utils.UNKNOWN_TYPE:
				gvars_to_propagate.append(obj_ea)

		for obj_ea in gvars_to_propagate:
			upd = self.propagate_gvar_down(obj_ea)
			self.lvar2tinfo.update(upd)

		super().apply_analysis()
		self.vtable_analyzer.apply_analysis()

	def clear_analysis(self):
		super().clear_analysis()
		self.vtable_analyzer.clear_analysis()

	def get_lvar_uses(self, func_ea:int, lvar_id:int):
		var_uses = VarUses()
		func_aa = self.get_ast_analysis(func_ea)
		for wr in func_aa.var_assigns:
			if wr.var.varid != lvar_id: continue
			atype = self.analyze_cexpr(func_ea, wr.value)
			if atype is not utils.UNKNOWN_TYPE:
				var_uses.assigns.append(atype)

		for w in self.get_lvar_writes(func_ea, lvar_id):
			var_uses.writes.append(w)
		for c in self.get_lvar_call_arg_casts(func_ea, lvar_id):
			var_uses.casts.append(c)
		var_uses.casts = [c for c in self.get_lvar_call_arg_casts(func_ea, lvar_id)]
		return var_uses

	def get_lvar_writes(self, func_ea:int, lvar_id:int):
		func_aa = self.get_ast_analysis(func_ea)
		for var_write in func_aa.iterate_lvar_writes(lvar_id):
			write_type = self.analyze_cexpr(func_ea, var_write.value)
			# write exists, just type is unknown. will use simple int instead
			if write_type is utils.UNKNOWN_TYPE:
				write_type = utils.get_int_tinfo(var_write.value.type.get_size())
			var_write.value_type = write_type
			yield var_write

	def get_lvar_call_arg_casts(self, func_ea:int, lvar_id:int):
		func_aa = self.get_ast_analysis(func_ea)
		for call_cast in func_aa.iterate_lvar_call_casts(lvar_id):
			address = call_cast.func_call.address
			if address == -1:
				continue

			cast_type = call_cast.arg_type
			if cast_type is None or cast_type is utils.UNKNOWN_TYPE:
				cast_type = self.analyze_lvar(address, call_cast.arg_id)
				call_cast.arg_type = cast_type
			yield call_cast

	def analyze_gvar_type_by_assigns(self, gvar_ea:int) -> idaapi.tinfo_t:
		# analyzing gvar type by assigns to it
		funcs = set(utils.get_func_calls_to(gvar_ea))
		assigns = []
		for func_ea in funcs:
			aa = self.get_ast_analysis(func_ea)
			for ga in aa.var_assigns:
				if ga.var.varid == gvar_ea:
					assigns.append((func_ea, ga))

		if len(assigns) != 1:
			return utils.UNKNOWN_TYPE

		assign_ea, gvar_assign = assigns[0]
		return self.analyze_cexpr(assign_ea, gvar_assign.value)

	def analyze_gvar(self, gvar_ea:int) -> idaapi.tinfo_t:
		current_type = self.gvar2tinfo.get(gvar_ea)
		if current_type is not None:
			return current_type

		vtbl = self.vtable_analyzer.analyze_gvar(gvar_ea)
		if vtbl is not utils.UNKNOWN_TYPE:
			return vtbl

		gvar_type = self.analyze_gvar_type_by_assigns(gvar_ea)
		self.gvar2tinfo[gvar_ea] = gvar_type
		return gvar_type

	def analyze_cexpr(self, func_ea:int, cexpr:idaapi.cexpr_t) -> idaapi.tinfo_t:
		cexpr = utils.strip_casts(cexpr)

		if cexpr.op == idaapi.cot_var:
			return self.analyze_lvar(func_ea, cexpr.v.idx)

		if cexpr.op == idaapi.cot_call:
			call_ea = cexpr.x.obj_ea
			return self.analyze_retval(call_ea)

		if cexpr.op in {idaapi.cot_num}:
			return cexpr.type

		if cexpr.op == idaapi.cot_obj and not utils.is_func_start(cexpr.obj_ea):
			gvar_type = self.analyze_gvar(cexpr.obj_ea)
			if gvar_type is utils.UNKNOWN_TYPE:
				return utils.UNKNOWN_TYPE

			actual_type = utils.addr2tif(cexpr.obj_ea)
			if actual_type is None or actual_type.is_array():
				gvar_ptr_type = idaapi.tinfo_t()
				gvar_ptr_type.create_ptr(gvar_type)
				gvar_type = gvar_ptr_type
			return gvar_type

		if cexpr.op == idaapi.cot_ref and cexpr.x.op == idaapi.cot_obj and not utils.is_func_start(cexpr.x.obj_ea):
			gvar_type = self.analyze_gvar(cexpr.x.obj_ea)
			if gvar_type is utils.UNKNOWN_TYPE:
				return utils.UNKNOWN_TYPE

			gvar_ptr_type = idaapi.tinfo_t()
			gvar_ptr_type.create_ptr(gvar_type)
			return gvar_ptr_type

		print("WARNING:", "unknown cexpr value", cexpr.opname)
		return utils.UNKNOWN_TYPE

	def calculate_var_type_by_uses(self, var_uses: VarUses):
		assigns = var_uses.assigns
		casts = var_uses.casts
		writes = var_uses.writes

		if len(writes) == 0 and len(casts) == 0 and len(assigns) == 0:
			return utils.UNKNOWN_TYPE

		# signle assign can only be one type
		if len(assigns) == 1:
			return assigns[0]

		# try to resolve multiple assigns
		if len(assigns) > 1:
			# prefer types over non-types
			strucid_assigns = [a for a in assigns if utils.tif2strucid(a) != idaapi.BADADDR]
			if len(strucid_assigns) == 1:
				return strucid_assigns[0]
			# multiple different assignments is unknown
			else:
				return utils.UNKNOWN_TYPE

		# single write at offset 0 does not create new type
		if len(casts) == 0 and len(writes) == 1 and writes[0].is_ptr_write() and writes[0].get_ptr_write_offset() == 0:
			write_type = writes[0].value_type.copy()
			write_type.create_ptr(write_type)
			return write_type

		# single cast at offset 0 might be existing type
		if len(casts) == 1 and casts[0].offset == 0:
			cast_offset, arg_type = casts[0].offset, casts[0].arg_type

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
			cast_end = cast_offset + arg_type.get_size()
			for w in writes:
				write_start = w.get_ptr_write_offset()
				write_end = w.value_type.get_size()
				# write_start, write_end = w[0], w[1].get_size()
				if write_start < cast_offset or write_end > cast_end:
					return utils.UNKNOWN_TYPE

			arg_type.create_ptr(arg_type)
			return arg_type

		# TODO writes into array of one type casts, that start at offset 0
		# TODO check if all writes are to the same offset
		# TODO check if all writes are actually array writes at various offsets

		if len(writes) > 0 and any(not w.is_ptr_write() for w in writes):
			print("non-pointer writes are not suppoerted for now")
			return utils.UNKNOWN_TYPE

		lvar_struct = Structure.create()
		self.new_types.add(lvar_struct.strucid)
		lvar_tinfo = lvar_struct.ptr_tinfo

		for lvar_write in writes:
			self.add_member_type(lvar_struct.strucid, lvar_write.get_ptr_write_offset(), lvar_write.value_type)

		for cast in casts:
			arg_type = cast.arg_type
			# cast exists, just type is unknown. will use simple int instead
			if arg_type is utils.UNKNOWN_TYPE:
				arg_type = utils.get_int_tinfo(1)

			if arg_type.is_ptr():
				arg_type = arg_type.get_pointed_object()

			self.add_member_type(lvar_struct.strucid, cast.offset, arg_type)

		return lvar_tinfo

	def analyze_lvar(self, func_ea:int, lvar_id:int) -> idaapi.tinfo_t:
		current_lvar_tinfo = self.lvar2tinfo.get((func_ea, lvar_id))
		if current_lvar_tinfo is not None:
			return current_lvar_tinfo

		lvar_tinfo = self.get_var_type(func_ea, lvar_id)
		if lvar_tinfo is not utils.UNKNOWN_TYPE and utils.tif2strucid(lvar_tinfo) != idaapi.BADADDR:
			# TODO check correctness of writes, read, casts
			return lvar_tinfo

		# TODO check that var is not recursively dependant on itself
		# TODO check that var uses are compatible
		lvar_uses = self.get_lvar_uses(func_ea, lvar_id)
		lvar_tinfo = self.calculate_var_type_by_uses(lvar_uses)
		self.lvar2tinfo[(func_ea, lvar_id)] = lvar_tinfo
		return lvar_tinfo

	def analyze_retval(self, func_ea:int) -> idaapi.tinfo_t:
		rv = self.retval2tinfo.get(func_ea)
		if rv is not None:
			return rv

		aa = self.get_ast_analysis(func_ea)
		lvs = aa.get_returned_lvars()
		if len(lvs) == 1:
			retval_lvar_id = lvs.pop()
			retval = self.analyze_lvar(func_ea, retval_lvar_id)
		else:
			retval = utils.UNKNOWN_TYPE

		self.retval2tinfo[func_ea] = retval
		return retval

	def analyze_function(self, func_ea:int):
		if func_ea in self.analyzed_functions:
			return
		self.analyzed_functions.add(func_ea)

		for call_from_ea in utils.get_func_calls_from(func_ea):
			self.analyze_function(call_from_ea)

		for i in range(self.get_lvars_counter(func_ea)):
			self.analyze_lvar(func_ea, i)

		self.analyze_retval(func_ea)

	def is_ok_propagation_type(self, tif:idaapi.tinfo_t) -> bool:
		if tif is None or tif is utils.UNKNOWN_TYPE:
			return False
		strucid = utils.tif2strucid(tif)
		if strucid not in self.new_types:
			return False
		return True

	def propagate_lvar_down(self, func_ea:int, lvar_id:int):
		lvar_type = self.lvar2tinfo.get((func_ea, lvar_id))
		if not self.is_ok_propagation_type(lvar_type):
			return {}

		propagated_lvars = {}
		aa = self.get_ast_analysis(func_ea)
		for call_cast in aa.iterate_lvar_call_casts(lvar_id):
			call_ea = call_cast.func_call.address
			arg_id = call_cast.arg_id
			if call_ea == -1 or call_cast.offset != 0 or call_cast.cast_type != call_cast.VAR_CAST:
				continue

			current_type = self.lvar2tinfo.get((call_ea, arg_id))
			if current_type is None:
				current_type = propagated_lvars.get((call_ea, arg_id))

			if current_type == lvar_type:
				continue

			if current_type is None or current_type is utils.UNKNOWN_TYPE:
				propagated_lvars[(call_ea, arg_id)] = lvar_type
				upd = self.propagate_lvar_down(call_ea, arg_id)
				propagated_lvars.update(upd)
				continue
		return propagated_lvars

	def propagate_gvar_down(self, gvar_ea:int):
		gvar_type = self.gvar2tinfo.get(gvar_ea)
		if not self.is_ok_propagation_type(gvar_type):
			return {}

		propagated_lvars = {}
		funcs = set(utils.get_func_calls_to(gvar_ea))
		for func_ea in funcs:
			aa = self.get_ast_analysis(func_ea)
			for call_cast in aa.iterate_gvar_call_casts(gvar_ea):
				call_ea = call_cast.func_call.address
				if call_ea == -1 or call_cast.offset != 0 or call_cast.cast_type != call_cast.VAR_CAST:
					continue
				arg_id = call_cast.arg_id

				current_type = self.lvar2tinfo.get((call_ea, arg_id))
				if current_type is None:
					current_type = propagated_lvars.get((call_ea, arg_id))

				if current_type == gvar_type:
					continue

				if current_type is None or current_type is utils.UNKNOWN_TYPE:
					propagated_lvars[(call_ea, arg_id)] = gvar_type
					upd = self.propagate_lvar_down(call_ea, arg_id)
					propagated_lvars.update(upd)
					continue 

				print(
					"Error in gvar propagation of", hex(gvar_ea),
					"in", idaapi.get_name(func_ea),
					"to", idaapi.get_name(call_ea),
					"-- arg", arg_id, "has different type", current_type,
					"from gvar type", str(gvar_type),
					"\n",
				)
		return propagated_lvars