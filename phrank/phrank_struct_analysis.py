import phrank.phrank_hexrays as p_hrays
import phrank.phrank_containers as p_containers

class StructFactory:
	def __init__(self):
		return

	def analyze_variable(self, cfunc, var_id):
		fuv : p_hrays.FuncAnalysisVisitor = p_hrays.FuncAnalysisVisitor.create(addr=cfunc.entry_ea)
		func = fuv.get_func()
		func.set_cfunc(cfunc)
		var_size = fuv.get_var_use_size(var_id)
		var = func.get_var(var_id)
		if var_size == 0:
			return

		tif = var.tif
		if tif.is_ptr():
			tif = tif.get_pointed_object()

		if tif.is_struct():
			pass

		new_struct = p_containers.Struct()
		new_struct.resize(var_size)
		new_struct_tif = new_struct.get_tinfo()
		new_struct_tif.create_ptr(new_struct_tif)

		func.set_argvar_type(var_id, new_struct_tif)