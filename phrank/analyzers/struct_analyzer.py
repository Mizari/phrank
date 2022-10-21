from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.containers.structure import Structure

class StructAnalyzer(TypeAnalyzer):
	def __init__(self):
		super().__init__()

	def analyze_variable(self, cfunc, var_id, force_new_type=False):
		fuv = self.get_ast_analysis(cfunc.entry_ea)
		var_size = fuv.get_var_use_size(var_id)
		if var_size == 0:
			return

		var_type = self.get_var_type(var_id)
		if var_type is None:
			return

		if var_type.is_ptr():
			var_type = var_type.get_pointed_object()

		if var_type.is_struct() and not force_new_type:
			current_struct = Structure(name=str(var_type))
			if current_struct.get_size() < var_size:
				current_struct.resize(var_size)
		else:
			new_struct = Structure()
			new_struct.resize(var_size)
			new_struct_tif = new_struct.get_tinfo()
			new_struct_tif.create_ptr(new_struct_tif)

			self.set_var_type(var_id, new_struct_tif)