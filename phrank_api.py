
# forward imports
from phrank.analyzers.struct_analyzer import StructAnalyzer
from phrank.analyzers.vtable_analyzer import VtableAnalyzer
from phrank.analyzers.cpp_class_analyzer import CppClassAnalyzer
from phrank.ast_analyzer import ASTAnalyzer
from phrank.cfunction_factory import CFunctionFactory
import phrank.settings as settings

from phrank.utils import *
from phrank.ast_parts import *


def propagate_var(var:Var):
	struct_analyzer = StructAnalyzer()
	var_type = struct_analyzer.get_current_var_type(var)
	struct_analyzer.set_var_type(var, var_type)
	strucid = tif2strucid(var_type)
	struct_analyzer.new_types.add(strucid)
	struct_analyzer.propagate_var(var)
	struct_analyzer.apply_analysis()