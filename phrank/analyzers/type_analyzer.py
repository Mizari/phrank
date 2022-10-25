import idc

from phrank.containers.ida_struc_wrapper import IdaStrucWrapper
from phrank.function_facade import FunctionFacade
import phrank.util_aux as util_aux


class TypeAnalyzer(FunctionFacade):
	def __init__(self, func_factory=None) -> None:
		super().__init__(func_factory=func_factory)

		# analysis context
		# type analysis
		self.type2func = {}
		self.type2reads = {}
		self.type2writes = {}

		# analysis context
		# analyzed types without actually changing types
		self.lvar2tinfo = {}
		self.gvar2tinfo = {}
		self.field2tinfo = {}
		self.retval2tinfo = {}

		# analysis results
		self.new_types : list[IdaStrucWrapper] = []    # created types
		self.new_xrefs = []    # created xrefs
		self.new_lvars = []    # changed types of local variables
		self.new_gvars = []    # changed types of global variables
		self.new_fields = []   # changed types of struct fields
		self.new_retvals = []  # changed types of function return values

	def get_gvar_tinfo(self, gvar_ea) -> IdaStrucWrapper:
		gtype = self.gvar2tinfo.get(gvar_ea)
		if gtype is not None:
			return gtype

		gtype = idc.get_type(gvar_ea)
		if gtype is None:
			return None

		return util_aux.str2tif(gtype)

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

	def analyze_structure(self, struct):
		raise NotImplementedError

	def analyze_field(self, struct, offset):
		raise NotImplementedError