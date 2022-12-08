import idaapi

import phrank.phrank_settings as phrank_settings
import phrank.utils as utils

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

def decompile_function(func_ea):
	try:
		cfunc = idaapi.decompile(func_ea)
		str(cfunc)
		return cfunc
	except idaapi.DecompilationFailure:
		print("failed to decompile", hex(func_ea), idaapi.get_name(func_ea))
		return -1

class CFunctionFactory:
	def __init__(self):
		self.cached_cfuncs = {}

	def get_cfunc(self, func_ea: int):
		cfunc = self.cached_cfuncs.get(func_ea)
		if cfunc == -1:
			return None
		if cfunc is not None:
			return cfunc

		if not phrank_settings.DECOMPILE_RECURSIVELY:
			cfunc = decompile_function(func_ea)
			self.cached_cfuncs[func_ea] = cfunc
			return cfunc

		decompilation_queue = [func_ea]
		while len(decompilation_queue) != 0:
			func_ea = decompilation_queue[-1]
			new_functions_to_decompile = set()
			for subcall in utils.get_func_calls_from(func_ea):
				if subcall in self.cached_cfuncs: continue
				if subcall in decompilation_queue: continue
				new_functions_to_decompile.add(subcall)

			if len(new_functions_to_decompile) == 0:
				cfunc = decompile_function(func_ea)
				self.cached_cfuncs[func_ea] = cfunc
				decompilation_queue.pop()
			else:
				decompilation_queue += list(new_functions_to_decompile)

		cfunc = self.cached_cfuncs.get(func_ea)
		if cfunc == -1: cfunc = None
		return cfunc

	def clear_cfunc(self, func_ea: int):
		self.cached_cfuncs.pop(func_ea, None)

	def decompile_all(self):
		saved_decomp = phrank_settings.DECOMPILE_RECURSIVELY
		phrank_settings.DECOMPILE_RECURSIVELY = True
		for func_ea in utils.iterate_all_functions():
			self.get_cfunc(func_ea)
		phrank_settings.DECOMPILE_RECURSIVELY = saved_decomp