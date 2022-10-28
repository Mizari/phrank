import idaapi

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.containers.structure import Structure


class StructAnalyzer(TypeAnalyzer):
	def analyze_lvar(self, func_ea, lvar_id):
		if self.lvar2tinfo.get((func_ea, lvar_id)) is not None:
			return

		var_size = self.get_var_use_size(func_ea, lvar_id)
		if var_size == 0:
			return

		var_type = self.get_var_type(func_ea, lvar_id)
		if var_type is None:
			print("WARNING: unexpected variable type in", idaapi.get_name(func_ea), lvar_id)
			return

		if var_type.is_ptr():
			var_type = var_type.get_pointed_object()

			if var_type.is_struct():
				current_struct = Structure(struc_locator=str(var_type))
				if current_struct.get_size() < var_size:
					current_struct.resize(var_size)

			elif var_type.is_void() or var_type.is_integral():
				new_struct = Structure()
				new_struct.resize(var_size)
				self.new_types.append(new_struct)

				new_struct_tif = new_struct.get_tinfo()
				new_struct_tif.create_ptr(new_struct_tif)
				self.lvar2tinfo[(func_ea, lvar_id)] = new_struct_tif

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
		for i in self.get_lvars_counter(func_ea):
			self.analyze_lvar(func_ea, i)

		self.analyze_retval(func_ea)