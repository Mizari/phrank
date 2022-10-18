import phrank.util_aux as util_aux
import phrank.util_func as util_func

from phrank.analyzers.struct_analyzer import StructAnalyzer
from phrank.analyzers.vtable_analyzer import VtableAnalyzer
from phrank.analyzers.cpp_class_analyzer import CppClassAnalyzer


def analyze_everything():
	"""
	Starts analysis with all virtual tables. Then proceeds to analyze all functions from them.
	"""
	cpp_analyzer = CppClassAnalyzer()
	cpp_analyzer.analyze_everything()
	cpp_analyzer.apply_analysis()

def analyze_func(addr):
	"""
	Does a C++ analysis of a function.
	"""
	cpp_analyzer = CppClassAnalyzer()
	cpp_analyzer.analyze_func(addr)
	cpp_analyzer.apply_analysis()

def analyze_vtable(addr):
	"""
	Does a C++ analysis of a virtual table.
	"""
	cpp_analyzer = CppClassAnalyzer()
	cpp_analyzer.analyze_vtable(addr)
	cpp_analyzer.apply_analysis()

def analyze_variable(cfunc, var):
	"""
	Analyzes a memory pointer in a variable.
	"""
	struct_analyzer = StructAnalyzer()
	struct_analyzer.analyze_variable(cfunc, var)
	struct_analyzer.apply_analysis()

def create_vtables():
	vtbl_analyzer = VtableAnalyzer()
	vtbl_analyzer.analyze_everything()
	vtbl_analyzer.apply_analysis()

def create_vtable(addr):
	"""
	Creates a virtual table at given address.
	"""
	vtbl_analyzer = VtableAnalyzer()
	vtbl_analyzer.create_vtable(addr)
	vtbl_analyzer.apply_analysis()

def decompile_all():
	"""
	Decompiles all functions in the database recursively.
	"""
	fwrappers = [util_func.FuncWrapper(addr=fea) for fea in util_aux.iterate_all_functions()]
	fwrappers = filter(None, fwrappers)
	fwrappers = filter(lambda x: not x.should_skip_decompiling(), fwrappers)
	fwrappers = list(fwrappers)
	for fw in fwrappers:
		fw.decompile(decompile_recursively=True)