from phrank.ast_analysis import ASTAnalysis
from phrank.containers.ida_struc_wrapper import IdaStrucWrapper
from phrank.util_func import FuncWrapper


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
		self.new_types : list[IdaStrucWrapper] = []    # created types
		self.new_xrefs = []    # created xrefs
		self.new_lvars = []    # changed types of local variables
		self.new_gvars = []    # changed types of global variables
		self.new_fields = []   # changed types of struct fields
		self.new_retvals = []  # changed types of function return values

	def get_func_wrapper(self, func_ea: int) -> FuncWrapper:
		fw = self.cached_func_wrappers.get(func_ea)
		if fw is None:
			fw = FuncWrapper(addr=func_ea)
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
		# delete temporaly created new types
		for t in self.new_types:
			t.delete()
		self.new_types.clear()

	def apply_analysis(self):
		# new types are already created, simply skip them
		self.new_types.clear()

	def analyze_everything(self):
		raise NotImplementedError

	def analyze_function(self, func_ea):
		raise NotImplementedError

	def analyze_lvar(self, func_ea, lvar_id):
		raise NotImplementedError

	def analyze_gvar(self, gvar_ea):
		raise NotImplementedError

	def analyze_cexpr(self, cfunc, cexpr):
		raise NotImplementedError

	def analyze_field(self, struct, offset):
		raise NotImplementedError