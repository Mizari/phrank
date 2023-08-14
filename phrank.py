from __future__ import annotations

# forward imports
from pyphrank.analyzers.cpp_class_analyzer import CppClassAnalyzer
from pyphrank.analyzers.type_analyzer import TypeAnalyzer, select_type
from pyphrank.ast_analyzer import CTreeAnalyzer, get_var, get_var_use_chain, extract_vars
from pyphrank.cfunction_factory import CFunctionFactory
from pyphrank.containers.structure import Structure
from pyphrank.containers.union import Union
from pyphrank.containers.ida_struc_wrapper import IdaStrucWrapper
from pyphrank.containers.vtable import Vtable
from pyphrank.ast_analysis import ASTAnalysis, VarWrite
from pyphrank.ida_plugin import IDAPlugin
import pyphrank.settings as settings

from pyphrank.utils import *
from pyphrank.ast_parts import *


def get_plugin_instance():
    return IDAPlugin.get_instance()


def get_type_flow_graph(addr:int) -> ASTAnalysis|None:
    assert isinstance(addr, int)
    func_ea = get_func_start(addr)
    if func_ea == -1:
        log_err(f"{hex(addr)} is not a function")
        return None

    return TypeAnalyzer().get_ast_analysis(func_ea)


def print_type_flow_graph(addr:int):
    aa = get_type_flow_graph(addr)
    if aa is None:
        return

    func_ea = get_func_start(addr)
    aa.print_graph(f"{idaapi.get_name(func_ea)} TypeFlowGraph")