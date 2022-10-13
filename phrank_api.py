import functools

import phrank.util_aux as util_aux
import phrank.util_func as util_func
import phrank.util_ast as util_ast

from phrank.analyzers.struct_analyzer import StructAnalyzer
from phrank.analyzers.vtable_analyzer import VtableAnalyzer
from phrank.analyzers.cpp_vtable_analyzer import CppVtableAnalyzer
from phrank.analyzers.cpp_class_analyzer import CppClassAnalyzer


def analyze_everything():
	"""
	Starts analysis with all virtual tables. Then proceeds to analyze all functions from them.
	"""
	CppClassAnalyzer().analyze_everything()

def analyze_func(addr):
	"""
	Does a C++ analysis of a function.
	"""
	CppClassAnalyzer().analyze_func(addr)

def analyze_vtable(addr):
	"""
	Does a C++ analysis of a virtual table.
	"""
	CppClassAnalyzer().analyze_vtable(addr)

def analyze_variable(cfunc, var):
	"""
	Analyzes a memory pointer in a variable.
	"""
	StructAnalyzer().analyze_variable(cfunc, var)

def create_cpp_vtables():
	"""
	Creates C++ virtual tables in data segment
	"""
	CppVtableAnalyzer().create_all_vtables()

def create_vtables():
	VtableAnalyzer().create_all_vtables()

def create_vtable(addr):
	"""
	Creates a virtual table at given address.
	"""
	factory = VtableAnalyzer()
	return factory.create_vtable(addr=addr)

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