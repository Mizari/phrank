import idc

from phrank.containers.ida_struc_wrapper import IdaStrucWrapper
from phrank.function_manager import FunctionManager
import phrank.util_aux as util_aux


class TypeAnalyzer(FunctionManager):
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

		self.new_xrefs.clear()
		self.lvar2tinfo.clear()
		self.gvar2tinfo.clear()
		self.field2tinfo.clear()
		self.retval2tinfo.clear()

	def apply_analysis(self):
		# new types are already created, simply skip them
		self.new_types.clear()

		for (func_ea, lvar_id), new_type_tif in self.lvar2tinfo.items():
			self.set_var_type(func_ea, lvar_id, new_type_tif)

		for obj_ea, new_type_tif in self.gvar2tinfo.items():
			idc.SetType(obj_ea, str(new_type_tif) + ';')

		self.new_xrefs.clear()
		self.lvar2tinfo.clear()
		self.gvar2tinfo.clear()
		self.field2tinfo.clear()
		self.retval2tinfo.clear()

	def analyze_everything(self):
		raise NotImplementedError

	def analyze_function(self, func_ea):
		raise NotImplementedError

	def analyze_lvar(self, func_ea, lvar_id):
		raise NotImplementedError

	def analyze_retval(self, func_ea):
		raise NotImplementedError

	def analyze_gvar(self, gvar_ea):
		raise NotImplementedError

	def analyze_cexpr(self, cfunc, cexpr):
		raise NotImplementedError

	def analyze_structure(self, struct):
		raise NotImplementedError

	def analyze_field(self, struct, offset):
		raise NotImplementedError