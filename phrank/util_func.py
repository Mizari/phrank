from __future__ import annotations

import idc
import idaapi
import idautils
import phrank.phrank_settings as phrank_settings
import phrank.util_aux as util_aux

import re


def get_func(func_loc) -> idaapi.func_t:
	if isinstance(func_loc, int):
		addr = func_loc
	elif isinstance(func_loc, str):
		addr = idc.get_name_ea_simple(func_loc)
	else:
		raise TypeError("Invalid function location type, should be int|str")

	return idaapi.get_func(addr)

def get_func_start(func_loc):
	func = get_func(func_loc)
	if func is None:
		return idaapi.BADADDR
	return func.start_ea

class FuncWrapper(object):
	def __init__(self, func_loc):
		self.__func = get_func(func_loc)
		self.__cfunc : idaapi.cfunptr_t|None = None
		self.__is_decompiled : bool = False

	def get_start(self):
		return self._func.start_ea

	def get_name(self):
		return idaapi.get_name(self.get_start())

	def get_func_details(self):
		func_tinfo = self.get_tinfo()
		if func_tinfo is None:
			return None

		func_details = idaapi.func_type_data_t()
		rv = func_tinfo.get_func_details(func_details)
		if not rv:
			print("Failed to get func details in", self.get_name())
			return None
		return func_details

	def set_var_type(self, var_id, var_type):
		cfunc = self.get_cfunc()
		if cfunc is None:
			print("Failed to change variable type, because of decompilation failure in", self.get_name())
			return

		var = cfunc.lvars[var_id]
		# var.set_user_type()
		# var.set_final_lvar_type(var_type)

		info = idaapi.lvar_saved_info_t()
		info.ll = var
		info.type = var_type
		info.name = var.name
		rv = idaapi.modify_user_lvar_info(self.__func.start_ea, idaapi.MLI_TYPE, info)
		assert rv, "Failed to modify lvar"

		self.clear_decompile()
	
	def get_var(self, var_idx):
		return self.get_cfunc().lvars[var_idx]

	def get_arg_type(self, arg_id):
		# XXX do not refactor this into one liner, 
		# XXX because ida will lose arg type somewhere along the way
		fdet = self.get_func_details()
		if fdet is None:
			print("Failed to get func details in", self.get_name())
			return

		return fdet[arg_id].type.copy()

	def set_arg_type(self, arg_id, arg_type):
		if isinstance(arg_type, str):
			arg_type = util_aux.str2tif(arg_type)

		func_details = self.get_func_details()
		if func_details is None:
			print("Failed to change argument type (no func details) in", self.get_name())
			return

		func_details[arg_id].type = arg_type.copy()

		new_func_tinfo = idaapi.tinfo_t()
		rv = new_func_tinfo.create_func(func_details)
		assert rv, "Failed to create func tinfo from details"

		rv = idaapi.apply_tinfo(self.__func.start_ea, new_func_tinfo, 0)
		assert rv, "Failed to apply new tinfo to function"

		self.clear_decompile()

	def get_start(self):
		return self.__func.start_ea

	def is_movrax_ret(self):
		# count blocks
		blocks = [b for b in idautils.Chunks(self.get_start())]
		if len(blocks) > 1:
			return False
		block = blocks[0]

		# count instructions
		instrs = [h for h in idautils.Heads(block[0], block[1])]
		if len(instrs) != 2:
			return False

		# first is xor rax|eax
		disasm = idc.GetDisasm(instrs[0])
		p1 = re.compile("xor[ ]*(eax|rax), (eax|rax).*")  # mov rax, 0
		p2 = re.compile("mov[ ]*(eax|rax), \d+.*")        # mov rax, !0
		if re.fullmatch(p1, disasm) is None and re.fullmatch(p2, disasm) is None:
			return False

		# second is retn
		disasm = idc.GetDisasm(instrs[1])
		if not disasm.startswith("retn"):
			return False
		return True

	def get_tinfo(self):
		tif = idaapi.tinfo_t()

		cfunc = self.get_cfunc()
		if cfunc is not None:
			cfunc.get_func_type(tif)
			if tif.is_correct():
				return tif

		if idaapi.get_tinfo(tif, self.get_start()) and tif.is_correct():
			return tif

		if self.is_movrax_ret():
			tif = util_aux.get_voidfunc_tinfo()
			if tif.is_correct():
				return tif

		print("Failed to get tinfo for", hex(self.get_start()), self.get_name())
		return None

	def get_ptr_tinfo(self):
		tif = self.get_tinfo()
		if tif is None:
			return None
		rv = tif.create_ptr(tif)
		if rv == False:
			print("Failed to change tinfo of", str(tif))
			return None
		return tif

	def get_cfunc(self, decompile_recursively=False):
		if not self.__is_decompiled:
			self.decompile(decompile_recursively=decompile_recursively)

		return self.__cfunc

	def set_cfunc(self, cfunc):
		self.__is_decompiled = True
		self.__cfunc = cfunc

	def decompile(self, decompile_recursively=False):
		if self.__is_decompiled:
			return

		self.__is_decompiled = True

		if decompile_recursively or phrank_settings.DECOMPILE_RECURSIVELY:
			for subcall in util_aux.get_func_calls_from(self.get_start()):
				decompile(subcall, decompile_recursively=True)

		try:
			self.__cfunc = idaapi.decompile(self.get_start())
			str(self.__cfunc)
		except idaapi.DecompilationFailure:
			print("failed to decompile", hex(self.get_start()), self.get_name())
		return

	def clear_decompile(self):
		self.__is_decompiled = False
		self.__cfunc = None

	def get_nargs(self):
		return self.get_tinfo().get_nargs()

	def get_lvars_counter(self):
		cfunc = self.get_cfunc()
		if cfunc is None: return 0

		counter = 0
		for lv in cfunc.get_lvars():
			if lv.name == '':
				continue
			counter += 1
		return counter

	def should_skip_decompiling(self):
		fname = self.get_name()
		if fname is None:
			print("emtpy name %s" % hex(self.get_start()))
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

def get_func_tinfo(func_addr):
	return FuncWrapper(func_addr).get_tinfo()

def get_func_nargs(func_addr):
	return get_func_tinfo(func_addr).get_nargs()

def get_func_ptr_tinfo(func_addr):
	return FuncWrapper(func_addr).get_ptr_tinfo()

def get_func_cfunc(addr):
	return FuncWrapper(addr).get_cfunc()

def is_function_start(func_addr):
	return func_addr == get_func_start(func_addr)

def set_func_arg_type(addr, arg_id, arg_type):
	return FuncWrapper(addr).set_arg_type(arg_id, arg_type)

def get_func_arg_type(addr, arg_id):
	return FuncWrapper(addr).get_arg_type(arg_id)

def set_func_argvar_type(addr, arg_id, var_type):
	return FuncWrapper(addr).set_var_type(arg_id, var_type)

def decompile(addr, decompile_recursively=False):
	return FuncWrapper(addr).decompile(decompile_recursively=decompile_recursively)