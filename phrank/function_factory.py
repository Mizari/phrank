import idaapi

import phrank.phrank_settings as phrank_settings
import phrank.util_aux as util_aux

from phrank.ast_analysis import ASTAnalysis

def should_skip_decompiling(func_ea):
	fname = idaapi.get_name(func_ea)
	if fname is None:
		print("emtpy name %s" % hex(func_ea))
		return True

	if phrank_settings.should_skip_by_prefix(fname):
		return True

	# global constructors
	if fname.startswith("_GLOBAL__sub_I_"):
		return True

	dfname = idaapi.demangle_name(fname, idaapi.MNG_NODEFINIT | idaapi.MNG_NORETTYPE)
	if dfname is not None and phrank_settings.should_skip_by_prefix(dfname):
		return True

	return False

class FunctionFactory:
	def __init__(self, decompile_recursively = phrank_settings.DECOMPILE_RECURSIVELY):
		self.cached_ast_analysis = {}
		self.cached_func_wrappers = {}
		self.cached_cfuncs = {}
		self.decompile_recursively = decompile_recursively

	def get_ast_analysis(self, func_ea: int) -> ASTAnalysis:
		aa = self.cached_ast_analysis.get(func_ea)
		if aa is not None:
			return aa

		cfunc = self.get_cfunc(func_ea)
		aa = ASTAnalysis(cfunc)
		self.cached_ast_analysis[func_ea] = aa
		return aa

	def get_cfunc(self, func_ea: int):
		cfunc = self.cached_cfuncs.get(func_ea)
		if cfunc == idaapi.BADADDR:
			return None
		if cfunc is not None:
			return cfunc

		if self.decompile_recursively:
			for subcall in util_aux.get_func_calls_from(func_ea):
				self.get_cfunc(subcall)

		try:
			cfunc = idaapi.decompile(func_ea)
			str(cfunc)
			self.cached_cfuncs[func_ea] = cfunc
		except idaapi.DecompilationFailure:
			print("failed to decompile", hex(self.get_start()), self.get_name())
			self.cached_cfuncs[func_ea] = idaapi.BADADDR
		return cfunc

	def clear_cfunc(self, func_ea: int):
		self.cached_cfuncs.pop(func_ea, None)

	def decompile_all(self):
		saved_decomp = self.decompile_recursively
		self.decompile_recursively = True
		for func_ea in util_aux.iterate_all_functions():
			self.get_cfunc(func_ea)
		self.decompile_recursively = saved_decomp