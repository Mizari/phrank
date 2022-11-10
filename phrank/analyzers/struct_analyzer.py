import idaapi

import phrank.util_aux as util_aux

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.containers.structure import Structure
from phrank.util_ast import get_var_offset


class StructAnalyzer(TypeAnalyzer):
	def __init__(self, func_factory=None) -> None:
		super().__init__(func_factory)
		self.analyzed_functions = set()

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
				varid, offset = get_var_offset(arg)
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

	def calculate_lvar_type_usage(self, func_ea, lvar_id, new_lvar_tinfo):
		lvar_strucid = util_aux.tif2strucid(new_lvar_tinfo)
		if lvar_strucid == idaapi.BADADDR:
			return

		lvar_struct = Structure(struc_locator=lvar_strucid)
		var_size = self.get_var_use_size(func_ea, lvar_id)
		lvar_struct.maximize_size(var_size)

		func_aa = self.get_ast_analysis(func_ea)
		for var_write in func_aa.get_writes_into_var(lvar_id):
			write_offset = var_write.offset
			write_type = self.analyze_cexpr(func_ea, var_write.val)
			# write exists, just type is unknown. will use simple int instead
			if write_type is None:
				write_type = util_aux.get_int_tinfo(var_write.val.type.get_size())
			if lvar_struct.get_member_tinfo(write_offset) is None:
				lvar_struct.add_member(write_offset)
			lvar_struct.set_member_type(write_offset, write_type)

		for func_call in func_aa.get_calls():
			call_ea = func_call.get_ea()
			for arg_id, arg in enumerate(func_call.get_args()):
				varid, offset = get_var_offset(arg)
				if varid != lvar_id or offset == 0: continue

				if call_ea is None: continue
				arg_tinfo = self.analyze_lvar(call_ea, arg_id)
				if arg_tinfo is None: continue

				if not lvar_struct.member_exists(offset):
					lvar_struct.add_member(offset)
				lvar_struct.set_member_type(offset, arg_tinfo)

	def calculate_passed_lvar_type(self, func_ea, lvar_id):
		func_aa = self.get_ast_analysis(func_ea)
		offset0_lvar_passes = []
		for func_call in func_aa.get_calls():
			call_ea = func_call.get_ea()
			if call_ea is None: continue
			for arg_id, arg in enumerate(func_call.get_args()):
				varid, offset = get_var_offset(arg)
				if varid != lvar_id or offset != 0: continue
				new_lvar_tinfo = self.analyze_lvar(call_ea, arg_id)
				if new_lvar_tinfo is None: continue
				offset0_lvar_passes.append(new_lvar_tinfo)

		if len(offset0_lvar_passes) > 1:
			print("WARNING:", "multiple different types found for one local variable")
			print("WARNING:", "not implemented, will just use random one")

		if len(offset0_lvar_passes) > 0:
			return offset0_lvar_passes[0]
		else:
			return None

	def calculate_current_lvar_type(self, func_ea, lvar_id):
		func_aa = self.get_ast_analysis(func_ea)

		var_type = self.get_var_type(func_ea, lvar_id)
		if var_type is None:
			print("WARNING: unexpected variable type in", idaapi.get_name(func_ea), lvar_id)
			return None

		if var_type.is_ptr():
			pointed = var_type.get_pointed_object()

			if not pointed.is_correct():
				return None

			if pointed.is_struct():
				return var_type

			elif pointed.is_void() or pointed.is_integral():
				if len([w for w in func_aa.get_writes_into_var(lvar_id)]) == 0:
					return None
				lvar_struct = Structure()
				self.new_types.append(lvar_struct)
				return lvar_struct.get_ptr_tinfo()

			else:
				print("WARNING:", "unknown pointer tinfo", str(var_type), "in", idaapi.get_name(func_ea))
				return None

		elif var_type.is_void() or var_type.is_integral():
			if len([w for w in func_aa.get_writes_into_var(lvar_id)]) == 0:
				return None
			lvar_struct = Structure()
			self.new_types.append(lvar_struct)
			return lvar_struct.get_tinfo()

		else:
			print("WARNING:", "failed to create struct from tinfo", str(var_type), "in", idaapi.get_name(func_ea))
			return None

	def analyze_cexpr(self, func_ea, cexpr):
		if cexpr.op == idaapi.cot_call:
			call_ea = cexpr.x.obj_ea
			return self.analyze_retval(call_ea)

		if cexpr.op in {idaapi.cot_num}:
			return cexpr.type

		if cexpr.op == idaapi.cot_obj and util_aux.get_func_start(cexpr.obj_ea) == cexpr.obj_ea:
			return cexpr.type

		print("WARNING:", "unknown cexpr value", cexpr.opname)
		return None

	def calculate_assigned_lvar_type(self, func_ea, lvar_id):
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
		strucid_assigns = [a for a in assigns if util_aux.tif2strucid(a) != idaapi.BADADDR]
		if len(strucid_assigns) == 1:
			return strucid_assigns[0]

		print("WARNING:", "unknown assigned value in", idaapi.get_name(func_ea), "for", lvar_id)
		return None

	def calculate_lvar_type(self, func_ea, lvar_id):
		passed_lvar_type = self.calculate_passed_lvar_type(func_ea, lvar_id)
		if passed_lvar_type is not None:
			return passed_lvar_type

		assigned_lvar_type = self.calculate_assigned_lvar_type(func_ea, lvar_id)
		if assigned_lvar_type is not None:
			return assigned_lvar_type

		current_lvar_type = self.calculate_current_lvar_type(func_ea, lvar_id)
		if current_lvar_type is not None:
			return current_lvar_type

		return None

	def analyze_lvar(self, func_ea, lvar_id):
		current_lvar_tinfo = self.lvar2tinfo.get((func_ea, lvar_id))
		if current_lvar_tinfo is not None:
			return current_lvar_tinfo

		new_lvar_tinfo = self.calculate_lvar_type(func_ea, lvar_id)
		if new_lvar_tinfo is None:
			return None
		self.lvar2tinfo[(func_ea, lvar_id)] = new_lvar_tinfo

		# calculate only complex types modifications
		if util_aux.tif2strucid(new_lvar_tinfo) != idaapi.BADADDR:
			self.calculate_lvar_type_usage(func_ea, lvar_id, new_lvar_tinfo)

		return new_lvar_tinfo

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

		for call_from_ea in util_aux.get_func_calls_from(func_ea):
			self.analyze_function(call_from_ea)

		for i in self.get_lvars_counter(func_ea):
			self.analyze_lvar(func_ea, i)

		self.analyze_retval(func_ea)