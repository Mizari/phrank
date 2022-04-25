import idaapi

import phrank.phrank_cpp as phrank_cpp
import phrank.phrank_util as phrank_util
import phrank.phrank_func as phrank_func
import phrank.phrank_settings as phrank_settings
import phrank.phrank_containers as phrank_containers
import phrank.phrank_hexrays as phrank_hexrays
import phrank.phrank_struct_analysis as struct_analysis

def _analysis_api(func):
	def fwrapper(*args, should_clear_cache=True, **kwargs):
		rv = func(*args, **kwargs)
		if should_clear_cache:
			phrank_func.FuncWrapper.clear_cached_instances()
			phrank_hexrays.FuncAnalysisVisitor.clear_cached_instances()
		return rv
	return fwrapper

@_analysis_api
def analyze_everything():
	phrank_cpp.CppClassFactory().analyze_everything()

@_analysis_api
def analyze_func(addr):
	phrank_cpp.CppClassFactory().analyze_func(addr)

@_analysis_api
def analyze_vtable(addr):
	phrank_cpp.CppClassFactory().analyze_vtable(addr)

@_analysis_api
def analyze_variable(cfunc, var):
	struct_analysis.StructFactory().analyze_variable(cfunc, var)

@_analysis_api
def create_cpp_vtables():
	phrank_cpp.CppVtableFactory().create_all_vtables()

@_analysis_api
def create_vtables():
	phrank_containers.VtableFactory().create_all_vtables()

def create_vtable(addr):
	factory = phrank_containers.VtableFactory()
	return factory.create_vtable(addr=addr)

def decompile_all():
	fwrappers = [phrank_func.FuncWrapper(addr=fea) for fea in phrank_util.iterate_all_functions()]
	fwrappers = filter(None, fwrappers)
	fwrappers = filter(lambda x: not x.should_skip_decompiling(), fwrappers)
	fwrappers = list(fwrappers)
	for fw in fwrappers:
		fw.decompile(decompile_recursively=True)