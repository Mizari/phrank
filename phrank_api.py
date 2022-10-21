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
	vtbl_analyzer.analyze_gvar(addr)
	vtbl_analyzer.apply_analysis()