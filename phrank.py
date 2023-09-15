"""Aggregator module for all underlying phrank API"""

from __future__ import annotations

import sys

# forward imports
from pyphrank.type_constructors.cpp_class_constructor import CppClassAnalyzer
from pyphrank.type_analyzer import TypeAnalyzer
from pyphrank.ast_analyzer import CTreeAnalyzer, get_var, get_var_use_chain, extract_vars
from pyphrank.cfunction_factory import CFunctionFactory
from pyphrank.containers.structure import Structure
from pyphrank.containers.union import Union
from pyphrank.containers.ida_struc_wrapper import IdaStrucWrapper
from pyphrank.containers.vtable import Vtable
from pyphrank.type_flow_graph import TFG
from pyphrank.ida_plugin import IDAPlugin
from pyphrank.analysis_state import AnalysisState
import pyphrank.settings as settings

from pyphrank.utils import *
from pyphrank.type_flow_graph_parts import *


def get_plugin_instance():
    return IDAPlugin.get_instance()


def get_plugin_state() -> AnalysisState:
	return get_plugin_instance().type_analyzer.state


def apply_plugin_state():
	plugin = get_plugin_instance()
	plugin.type_analyzer.apply_analysis()


def get_type_flow_graph(addr:int) -> TFG|None:
    assert isinstance(addr, int)
    func_ea = get_func_start(addr)
    if func_ea == -1:
        log_err(f"{hex(addr)} is not a function")
        return None

    return TypeAnalyzer().get_tfg(func_ea)


def print_type_flow_graph(addr:int):
    aa = get_type_flow_graph(addr)
    if aa is None:
        return

    func_ea = get_func_start(addr)
    aa.print(f"{idaapi.get_name(func_ea)} TypeFlowGraph")

def __print_padded(*args, padlen=0):
	padlen -= 1
	print(' ' * padlen, *args, )


def __help_objects(name, objs):
	if len(objs) == 0:
		return

	print(name)
	for modname in sorted(objs.keys()):
		m = objs[modname]
		__print_padded(modname, padlen=4)
		if m.__doc__:
			__print_padded(m.__doc__, padlen=8)
		print()
	print()

def phrank_help():
	"""Print this help"""
	from inspect import isclass, isfunction, ismodule

	mod = sys.modules[__name__]
	funcs = {}
	modules = {}
	classes = {}
	skips = {"sys", "idaapi", "typing", "ida_struct", "re", "logging", "idautils", "idc", "Any", "utils"}
	for k, v in vars(mod).items():
		if k.startswith("__"): continue
		if k in skips:
			continue
		if isfunction(v):
			funcs[k] = v
		elif ismodule(v):
			modules[k] = v
		elif isclass(v):
			classes[k] = v
		else:
			pass

	print("DESCRIPTION")
	__print_padded(mod.__doc__, padlen=4)
	print()

	__help_objects("MODULES", modules)
	__help_objects("CLASSES", classes)
	__help_objects("FUNCTIONS", funcs)