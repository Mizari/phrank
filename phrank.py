
# forward imports
from pyphrank.analyzers.cpp_class_analyzer import CppClassAnalyzer
from pyphrank.analyzers.type_analyzer import TypeAnalyzer, VarUses, VarWrite, select_type
from pyphrank.ast_analyzer import CTreeAnalyzer, get_var, get_var_use_chain, extract_vars
from pyphrank.cfunction_factory import CFunctionFactory
from pyphrank.containers.structure import Structure
from pyphrank.containers.union import Union
from pyphrank.containers.ida_struc_wrapper import IdaStrucWrapper
from pyphrank.containers.vtable import Vtable
from pyphrank.ast_analysis import ASTAnalysis
from pyphrank.ida_plugin import IDAPlugin
import pyphrank.settings as settings

from pyphrank.utils import *
from pyphrank.ast_parts import *


def get_plugin_instance():
    return IDAPlugin.get_instance()