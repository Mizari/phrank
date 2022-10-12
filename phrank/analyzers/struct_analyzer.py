import phrank.util_ast as p_hrays

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.containers.structure import Structure

class StructAnalyzer(TypeAnalyzer):
	def __init__(self):
		super().__init__()

	def analyze_variable(self, cfunc, var_id, force_new_type=False):
		fuv : p_hrays.ASTAnalysis = p_hrays.ASTAnalysis.create(addr=cfunc.entry_ea)
		func = fuv.get_func()
		func.set_cfunc(cfunc)
		var_size = fuv.get_var_use_size(var_id)
		var = func.get_var(var_id)
		if var_size == 0:
			return

		current_type = var.tif
		if current_type.is_ptr():
			current_type = current_type.get_pointed_object()

		if current_type.is_struct() and not force_new_type:
			current_struct = Structure(name=str(current_type))
			if current_struct.get_size() < var_size:
				current_struct.resize(var_size)
		else:
			new_struct = Structure()
			new_struct.resize(var_size)
			new_struct_tif = new_struct.get_tinfo()
			new_struct_tif.create_ptr(new_struct_tif)

			func.set_var_type(var_id, new_struct_tif)