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

	def analyze_lvar(self, func_ea, lvar_id):
		current_lvar_tinfo = self.lvar2tinfo.get((func_ea, lvar_id))
		if current_lvar_tinfo is not None:
			return current_lvar_tinfo

		func_aa = self.get_ast_analysis(func_ea)
		offset0_lvar_passes = []
		for func_call in func_aa.get_calls():
			call_ea = func_call.get_ea()
			if call_ea is None: continue
			for arg_id, arg in enumerate(func_call.get_args()):
				varid, offset = get_var_offset(arg)
				if varid != lvar_id: continue
				self.analyze_lvar(call_ea, arg_id)

				if offset == 0:
					lvar_tinfo = self.get_analyzed_lvar_type(call_ea, arg_id)
					if lvar_tinfo is None: continue
					offset0_lvar_passes.append(lvar_tinfo)

		if len(offset0_lvar_passes) > 1:
			print("WARNING:", "multiple different types found for one local variable, not implemented")
			print("will just use random one")

		if len(offset0_lvar_passes) > 0:
			lvar_tinfo = offset0_lvar_passes[0]
			self.lvar2tinfo[(func_ea, lvar_id)] = lvar_tinfo
			return lvar_tinfo

		var_size = self.get_var_use_size(func_ea, lvar_id)
		if var_size == 0:
			return None

		var_type = self.get_var_type(func_ea, lvar_id)
		if var_type is None:
			print("WARNING: unexpected variable type in", idaapi.get_name(func_ea), lvar_id)
			return None

		if var_type.is_ptr():
			var_type = var_type.get_pointed_object()

			if var_type.is_struct():
				current_struct = Structure(struc_locator=str(var_type))
				current_struct.maximize_size(var_size)
				self.lvar2tinfo[(func_ea, lvar_id)] = current_struct.get_ptr_tinfo()
				return current_struct.get_ptr_tinfo()

			elif var_type.is_void() or var_type.is_integral():
				new_struct = Structure()
				new_struct.resize(var_size)
				self.new_types.append(new_struct)

				new_lvar_tinfo = new_struct.get_ptr_tinfo()
				self.lvar2tinfo[(func_ea, lvar_id)] = new_lvar_tinfo
				return new_lvar_tinfo

		elif var_type.is_void() or var_type.is_integral():
			new_struct = Structure()
			new_struct.resize(var_size)
			self.new_types.append(new_struct)

			new_lvar_tinfo = new_struct.get_tinfo()
			self.lvar2tinfo[(func_ea, lvar_id)] = new_lvar_tinfo
			return new_lvar_tinfo

		else:
			print("WARNING:", "failed to create struct from tinfo", str(var_type), "in", idaapi.get_name(func_ea))
			return None

	def analyze_retval(self, func_ea):
		rv = self.retval2tinfo.get(func_ea)
		if rv is not None:
			return rv

		aa = self.get_ast_analysis(func_ea)
		lvs = aa.get_returned_lvars()
		if len(lvs) == 1:
			retval_lvar_id = lvs.pop()
			self.analyze_lvar(retval_lvar_id)

	def analyze_function(self, func_ea):
		if func_ea in self.analyzed_functions:
			return
		self.analyzed_functions.add(func_ea)

		for call_from_ea in util_aux.get_func_calls_from(func_ea):
			self.analyze_function(call_from_ea)

		for i in self.get_lvars_counter(func_ea):
			self.analyze_lvar(func_ea, i)

		self.analyze_retval(func_ea)