
import phrank.util_ast as util_ast


class TypeAnalyzer:
	def __init__(self) -> None:
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

	def get_ast_analysis(func_ea: int) -> util_ast.ASTAnalysis:
		return util_ast.ASTAnalysis(addr=func_ea)

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