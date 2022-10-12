import functools

import phrank.phrank_util as phrank_util
import phrank.phrank_func as phrank_func
import phrank.phrank_hexrays as phrank_hexrays

from phrank.analyzers.struct_analyzer import StructAnalyzer
from phrank.analyzers.vtable_analyzer import VtableAnalyzer
from phrank.analyzers.cpp_vtable_analyzer import CppVtableAnalyzer
from phrank.analyzers.cpp_class_analyzer import CppClassAnalyzer

def _analysis_api(func):
	@functools.wraps(func)
	def fwrapper(*args, should_clear_cache=True, **kwargs):
		rv = func(*args, **kwargs)
		if should_clear_cache:
			phrank_func.FuncWrapper.clear_cached_instances()
			phrank_hexrays.ASTAnalysis.clear_cached_instances()
			VtableAnalyzer().clear_created_vtables()
			CppVtableAnalyzer().clear_created_vtables()
		return rv
	return fwrapper

@_analysis_api
def analyze_everything():
	"""
	Starts analysis with all virtual tables. Then proceeds to analyze all functions from them.
	"""
	CppClassAnalyzer().analyze_everything()

@_analysis_api
def analyze_func(addr):
	"""
	Does a C++ analysis of a function.
	"""
	CppClassAnalyzer().analyze_func(addr)

@_analysis_api
def analyze_vtable(addr):
	"""
	Does a C++ analysis of a virtual table.
	"""
	CppClassAnalyzer().analyze_vtable(addr)

@_analysis_api
def analyze_variable(cfunc, var):
	"""
	Analyzes a memory pointer in a variable.
	"""
	StructAnalyzer().analyze_variable(cfunc, var)

@_analysis_api
def create_cpp_vtables():
	"""
	Creates C++ virtual tables in data segment
	"""
	CppVtableAnalyzer().create_all_vtables()

@_analysis_api
def create_vtables():
	VtableAnalyzer().create_all_vtables()

def create_vtable(addr):
	"""
	Creates a virtual table at given address.
	"""
	factory = VtableAnalyzer()
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