import idaapi

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.containers.structure import Structure
from phrank.util_aux import get_func_calls_to


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