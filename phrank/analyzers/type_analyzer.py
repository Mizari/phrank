
from phrank.ast_analyzer import ASTAnalysis
import phrank.util_func as util_func


class TypeAnalyzer:
	def __init__(self) -> None:
		self.cached_ast_analysis = {}
		self.cached_func_wrappers = {}

		# analysis context
		# type analysis
		self.type2func = {}
		self.type2reads = {}
		self.type2writes = {}

		# analysis context
		# analyzed types without actually changing types
		self.lvar2type = {}
		self.gvar2type = {}
		self.field2type = {}
		self.retval2type = {}

		# analysis results
		self.new_types = []    # created types
		self.new_xrefs = []    # created xrefs
		self.new_lvars = []    # changed types of local variables
		self.new_gvars = []    # changed types of global variables
		self.new_fields = []   # changed types of struct fields
		self.new_retvals = []  # changed types of function return values

	def get_func_wrapper(self, func_ea: int) -> util_func.FuncWrapper:
		fw = self.cached_func_wrappers.get(func_ea)
		if fw is None:
			fw = util_func.FuncWrapper(addr=func_ea)
			self.cached_func_wrappers[func_ea] = fw
		return fw

	def get_ast_analysis(self, func_ea: int) -> ASTAnalysis:
		aa = self.cached_ast_analysis.get(func_ea)
		if aa is not None:
			return aa

		fw = self.get_func_wrapper(func_ea)
		cfunc = fw.get_cfunc()
		aa = ASTAnalysis(cfunc)
		self.cached_ast_analysis[func_ea] = aa
		return aa

	def clear_analysis(self):
		return

	def apply_analysis(self):
		return

	def analyze_everything(self):
		return

	def analyze_function(self):
		return

	def analyze_lvar(self):
		return

	def analyze_gvar(self):
		return

	def analyze_cexpr(self):
		return

	def analyze_field(self):
		return