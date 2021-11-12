import idaapi
idaapi.require("phrank_func")
idaapi.require("phrank_cpp")
idaapi.require("phrank_containers")
idaapi.require("phrank_hexrays")
idaapi.require("phrank_util")

import phrank_cpp
import phrank_containers

def analyze_everything():
	phrank_cpp.CppClassFactory().analyze_everything()

def analyze_func(addr):
	phrank_cpp.CppClassFactory().analyze_func(addr)

def analyze_vtable(addr):
	phrank_cpp.CppClassFactory().analyze_vtable(addr)

def create_cpp_vtables():
	phrank_cpp.CppVtableFactory().create_all_vtables()

def create_vtables():
	phrank_containers.VtableFactory().create_all_vtables()