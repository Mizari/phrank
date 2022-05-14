import idaapi
import functools

import phrank.phrank_cpp as phrank_cpp
import phrank.phrank_util as phrank_util
import phrank.phrank_func as phrank_func
import phrank.phrank_hexrays as phrank_hexrays
import phrank.phrank_struct_analysis as struct_analysis

from phrank.containers.vtable import VtableFactory

def _analysis_api(func):
	@functools.wraps(func)
	def fwrapper(*args, should_clear_cache=True, **kwargs):
		rv = func(*args, **kwargs)
		if should_clear_cache:
			phrank_func.FuncWrapper.clear_cached_instances()
			phrank_hexrays.FuncAnalysisVisitor.clear_cached_instances()
			VtableFactory().clear_created_vtables()
			phrank_cpp.CppVtableFactory().clear_created_vtables()
		return rv
	return fwrapper

@_analysis_api
def analyze_everything():
	"""
	Starts analysis with all virtual tables. Then proceeds to analyze all functions from them.
	"""
	phrank_cpp.CppClassFactory().analyze_everything()

@_analysis_api
def analyze_func(addr):
	"""
	Does a C++ analysis of a function.
	"""
	phrank_cpp.CppClassFactory().analyze_func(addr)

@_analysis_api
def analyze_vtable(addr):
	"""
	Does a C++ analysis of a virtual table.
	"""
	phrank_cpp.CppClassFactory().analyze_vtable(addr)

@_analysis_api
def analyze_variable(cfunc, var):
	"""
	Analyzes a memory pointer in a variable.
	"""
	struct_analysis.StructFactory().analyze_variable(cfunc, var)

@_analysis_api
def create_cpp_vtables():
	"""
	Creates C++ virtual tables in data segment
	"""
	phrank_cpp.CppVtableFactory().create_all_vtables()

@_analysis_api
def create_vtables():
	VtableFactory().create_all_vtables()

def create_vtable(addr):
	"""
	Creates a virtual table at given address.
	"""
	factory = VtableFactory()
	return factory.create_vtable(addr=addr)

@_analysis_api
def decompile_all():
	"""
	Decompiles all functions in the database recursively.
	"""
	fwrappers = [phrank_func.FuncWrapper(addr=fea) for fea in phrank_util.iterate_all_functions()]
	fwrappers = filter(None, fwrappers)
	fwrappers = filter(lambda x: not x.should_skip_decompiling(), fwrappers)
	fwrappers = list(fwrappers)
	for fw in fwrappers:
		fw.decompile(decompile_recursively=True)