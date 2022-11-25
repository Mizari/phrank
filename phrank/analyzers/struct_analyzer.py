import idaapi

import phrank.utils as utils

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.analyzers.vtable_analyzer import VtableAnalyzer
from phrank.containers.structure import Structure


class StructAnalyzer(TypeAnalyzer):
	def __init__(self, func_factory=None) -> None:
		super().__init__(func_factory)
		self.analyzed_functions = set()
		self.vtable_analyzer = VtableAnalyzer(func_factory)

	def get_lvar_writes(self, func_ea, lvar_id):
		func_aa = self.get_ast_analysis(func_ea)
		for var_write in func_aa.get_writes_into_var(lvar_id):
			write_offset = var_write.offset
			write_type = self.analyze_cexpr(func_ea, var_write.val)
			# write exists, just type is unknown. will use simple int instead
			if write_type is None:
				write_type = utils.get_int_tinfo(var_write.val.type.get_size())
			yield write_offset, write_type

	def get_lvar_call_arg_casts(self, func_ea, lvar_id):
		func_aa = self.get_ast_analysis(func_ea)
		for func_call in func_aa.get_calls():
			call_ea = func_call.get_ea()
			for arg_id, arg in enumerate(func_call.get_args()):
				varid, offset = utils.get_var_offset(arg)
				if varid != lvar_id or offset == 0: continue

				# if helper function, then skip
				if call_ea is None: continue


				arg_tinfo = self.analyze_lvar(call_ea, arg_id)
				if arg_tinfo is None: continue

				if arg_tinfo.is_ptr() and offset != 0:
					arg_tinfo = arg_tinfo.get_pointed_object()

				yield offset, arg_tinfo

	def get_var_use_size(self, func_ea:int, lvar_id:int) -> int:
		func_aa = self.get_ast_analysis(func_ea)
		max_var_use = func_aa.get_var_use_size(lvar_id)

		for func_call in func_aa.get_calls():
			known_func_var_use = func_call.get_var_use_size(lvar_id)
			if known_func_var_use != 0:
				max_var_use = max(max_var_use, known_func_var_use)
				continue

			call_ea = func_call.get_ea()
			if call_ea is None: continue 

			for arg_id, arg in enumerate(func_call.get_args()):
				varid, offset = utils.get_var_offset(arg)
				if varid == -1:
					continue

				if varid != lvar_id:
					continue

				var_use = self.get_var_use_size(call_ea, arg_id)
				max_var_use = max(max_var_use, var_use + offset)

		return max_var_use

	def get_analyzed_lvar_type(self, func_ea, lvar_id):
		lvar_tinfo = self.lvar2tinfo.get((func_ea, lvar_id))
		if lvar_tinfo is not None:
			return lvar_tinfo
		return self.analyze_lvar(func_ea, lvar_id)

	def calculate_lvar_type_usage(self, func_ea, lvar_id, lvar_struct: Structure):
		var_size = self.get_var_use_size(func_ea, lvar_id)
		lvar_struct.maximize_size(var_size)

		for write_offset, write_type in self.get_lvar_writes(func_ea, lvar_id):
			if not lvar_struct.member_exists(write_offset):
				lvar_struct.add_member(write_offset)
			lvar_struct.set_member_type(write_offset, write_type)

		for offset, arg_tinfo in self.get_lvar_call_arg_casts(func_ea, lvar_id):
			if not lvar_struct.member_exists(offset):
				lvar_struct.add_member(offset)
			lvar_struct.set_member_type(offset, arg_tinfo)

	def analyze_existing_lvar_type_by_uses(self, func_ea, lvar_id):
		writes = [w for w in self.get_lvar_writes(func_ea, lvar_id)]
		casts = [c for c in self.get_lvar_call_arg_casts(func_ea, lvar_id)]

		if len(casts) == 0:
			# single write at offset 0 does not create new type
			if len(writes) == 1 and writes[0][0] == 0:
				_, write_type = writes[0]
				write_type.create_ptr(write_type)
				return write_type

			# multiple writes or write to not 0 is a complex type
			# TODO check if all writes are to the same offset
			# TODO check if all writes are actually array writes at various offsets
			else:
				return None

		if len(writes) == 0:
			if len(casts) == 1:
				# simple variable passing does not create new type
				if casts[0][0] == 0:
					return casts[0][1]

				# single cast at non-zero offset is a complex type
				else:
					return None

			# only passes of lvar to other functions, without creating new type here
			# writes that do not go out of the bounds of passed types is OK
			else:
				# if casts are of different types, then type is complex
				first_cast_type = casts[0][1]
				for _, cast_type in casts[1:]:
					if cast_type != first_cast_type:
						return None

				# TODO check if multiple cast at single offset
				# TODO if offsets are not continous, then type is complex
				# otherwise return array of cast types
				return None

		# TODO writes+casts
		return None

	def calculate_new_lvar_type(self, func_ea, lvar_id, struc_tinfo):
		func_aa = self.get_ast_analysis(func_ea)

		var_type = self.get_var_type(func_ea, lvar_id)
		if var_type is None:
			print("WARNING: unexpected variable type in", idaapi.get_name(func_ea), lvar_id)
			return None

		if var_type.is_ptr():
			pointed = var_type.get_pointed_object()

			if not pointed.is_correct():
				if func_aa.count_writes_into_var(lvar_id) == 0:
					return None
				else:
					struc_tinfo.create_ptr(struc_tinfo)
					return struc_tinfo

			if pointed.is_struct():
				return struc_tinfo

			elif pointed.is_void() or pointed.is_integral():
				if func_aa.count_writes_into_var(lvar_id) == 0:
					return None
				struc_tinfo.create_ptr(struc_tinfo)
				return struc_tinfo

			else:
				print("WARNING:", "unknown pointer tinfo", str(var_type), "in", idaapi.get_name(func_ea))
				return None

		elif var_type.is_void() or var_type.is_integral():
			if func_aa.count_writes_into_var(lvar_id) == 0:
				return None
			return struc_tinfo

		else:
			print("WARNING:", "failed to create struct from tinfo", str(var_type), "in", idaapi.get_name(func_ea))
			return None

	def analyze_gvar(self, gvar_ea):
		vtbl = self.vtable_analyzer.analyze_gvar(gvar_ea)
		if vtbl is not None:
			return vtbl

		return None

	def analyze_cexpr(self, func_ea, cexpr):
		if cexpr.op == idaapi.cot_call:
			call_ea = cexpr.x.obj_ea
			return self.analyze_retval(call_ea)

		if cexpr.op in {idaapi.cot_num}:
			return cexpr.type

		if cexpr.op == idaapi.cot_obj and not utils.is_func_start(cexpr.obj_ea):
			gvar_type = self.analyze_gvar(cexpr.obj_ea)
			if gvar_type is None:
				return None

			actual_type = utils.addr2tif(cexpr.obj_ea)
			if actual_type is None or actual_type.is_array():
				gvar_type.create_ptr(gvar_type)
			return gvar_type

		if cexpr.op == idaapi.cot_ref and cexpr.x.op == idaapi.cot_obj and not utils.is_func_start(cexpr.x.obj_ea):
			gvar_type = self.analyze_gvar(cexpr.x.obj_ea)
			if gvar_type is None:
				return None

			gvar_type.create_ptr(gvar_type)
			return gvar_type

		print("WARNING:", "unknown cexpr value", cexpr.opname)
		return None

	def analyze_existing_lvar_type_by_assigns(self, func_ea, lvar_id):
		func_aa = self.get_ast_analysis(func_ea)
		assigns = []
		for wr in func_aa.var_writes():
			if wr.varid != lvar_id: continue
			atype = self.analyze_cexpr(func_ea, wr.val)
			if atype is not None:
				assigns.append(atype)

		if len(assigns) == 0:
			return None
		elif len(assigns) == 1:
			return assigns[0]

		# prefer types over non-types
		strucid_assigns = [a for a in assigns if utils.tif2strucid(a) != idaapi.BADADDR]
		if len(strucid_assigns) == 1:
			return strucid_assigns[0]

		print("WARNING:", "unknown assigned value in", idaapi.get_name(func_ea), "for", lvar_id)
		return None

	def analyze_existing_lvar_type(self, func_ea, lvar_id):
		lvar_tinfo = self.get_var_type(func_ea, lvar_id)
		if lvar_tinfo is not None and utils.tif2strucid(lvar_tinfo) != idaapi.BADADDR:
			# TODO check correctness of writes, read, casts
			return lvar_tinfo

		lvar_tinfo = self.analyze_existing_lvar_type_by_assigns(func_ea, lvar_id)
		if lvar_tinfo is None:
			lvar_tinfo = self.analyze_existing_lvar_type_by_uses(func_ea, lvar_id)

		if lvar_tinfo is not None:
			# TODO check correctness of writes, read, casts
			pass

		return lvar_tinfo

	def analyze_new_lvar_type(self, func_ea, lvar_id):
		lvar_struct = Structure()
		lvar_tinfo = self.calculate_new_lvar_type(func_ea, lvar_id, lvar_struct.get_tinfo())
		if lvar_tinfo is None:
			lvar_struct.delete()
			return None
		else:
			self.new_types.append(lvar_struct.strucid)

		self.calculate_lvar_type_usage(func_ea, lvar_id, lvar_struct)
		return lvar_tinfo

	def analyze_lvar(self, func_ea, lvar_id):
		current_lvar_tinfo = self.lvar2tinfo.get((func_ea, lvar_id))
		if current_lvar_tinfo is not None:
			return current_lvar_tinfo

		lvar_tinfo = self.analyze_existing_lvar_type(func_ea, lvar_id)
		if lvar_tinfo is None:
			lvar_tinfo = self.analyze_new_lvar_type(func_ea, lvar_id)

		if lvar_tinfo is None:
			return None

		self.lvar2tinfo[(func_ea, lvar_id)] = lvar_tinfo
		return lvar_tinfo

	def analyze_retval(self, func_ea):
		rv = self.retval2tinfo.get(func_ea)
		if rv is not None:
			return rv

		aa = self.get_ast_analysis(func_ea)
		lvs = aa.get_returned_lvars()
		if len(lvs) == 1:
			retval_lvar_id = lvs.pop()
			return self.analyze_lvar(func_ea, retval_lvar_id)

		return None

	def analyze_function(self, func_ea):
		if func_ea in self.analyzed_functions:
			return
		self.analyzed_functions.add(func_ea)

		for call_from_ea in utils.get_func_calls_from(func_ea):
			self.analyze_function(call_from_ea)

		for i in range(self.get_lvars_counter(func_ea)):
			self.analyze_lvar(func_ea, i)

		self.analyze_retval(func_ea)