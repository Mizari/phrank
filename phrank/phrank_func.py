import idc
import idaapi
import idautils
import phrank.phrank_settings as phrank_settings
import phrank.phrank_util as p_util
from typing import Optional

import re


def get_func(*args, **kwargs):
	addr = None
	if len(args) != 0:
		if isinstance(args[0], int):
			addr = args[0]
		elif isinstance(args[0], str):
			funcname = args[0]
			addr = idc.get_name_ea_simple(funcname)
		if addr is not None:
			return idaapi.get_func(addr)

	addr = kwargs.get("addr", None)
	if addr is None:
		funcname = kwargs.get("name", None)
		if funcname is None:
			raise BaseException("No addr and no name are given, need one from them")
		addr = idc.get_name_ea_simple(funcname)

	func = idaapi.get_func(addr)
	return func

def get_func_start(*args, **kwargs):
	func = get_func(*args, **kwargs)
	if func is None:
		return idaapi.BADADDR
	return func.start_ea

@p_util.unique(get_func_start)
class FuncWrapper(object):
	__slots__ = "__func", "__cfunc", "__is_decompiled"
	_instances = {}

	def get_start(self):
		return self._func.start_ea

	def __init__(self, *args, **kwargs):
		func = get_func(*args, **kwargs)
		if func is None:
			print("ERROR:", args, kwargs)
			raise BaseException("Failed to get function start")

		self.__func : idaapi.func_t = func
		self.__cfunc : Optional[idaapi.cfunptr_t] = None
		self.__is_decompiled : bool = False

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
			arg_type = p_util.str2tif(arg_type)

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
			tif = p_util.get_voidfunc_tinfo()
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
			for subcall in p_util.get_func_calls_from(self.get_start()):
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
	f: FuncWrapper = FuncWrapper.create(addr=func_addr, noraise=True)
	if f is None:
		return None
	return f.get_tinfo()

def get_func_nargs(func_addr):
	ftif = get_func_tinfo(func_addr)
	return ftif.get_nargs()

def get_func_ptr_tinfo(func_addr):
	f: FuncWrapper = FuncWrapper.create(addr=func_addr, noraise=True)
	if f is None:
		return None
	
	return f.get_ptr_tinfo()

def get_func_cfunc(addr):
	f: FuncWrapper = FuncWrapper.create(addr=addr, noraise=True)
	if f is None:
		return None
	return f.get_cfunc()

def is_function_start(func_addr):
	return func_addr == get_func_start(func_addr)

def set_func_arg_type(addr, arg_id, arg_type):
	f: FuncWrapper = FuncWrapper.create(addr=addr, noraise=True)
	if f is None:
		raise BaseException("No such function")
	return f.set_arg_type(arg_id, arg_type)

def get_func_arg_type(addr, arg_id):
	f: FuncWrapper = FuncWrapper.create(addr=addr, noraise=True)
	if f is None:
		raise BaseException("No such function")
	return f.get_arg_type(arg_id)

def set_func_argvar_type(addr, arg_id, var_type):
	f: FuncWrapper = FuncWrapper.create(addr=addr, noraise=True)
	if f is None:
		raise BaseException("No such function")
	return f.set_var_type(arg_id, var_type)

def decompile(addr, decompile_recursively=False):
	f: FuncWrapper = FuncWrapper.create(addr=addr, noraise=True)
	if f is None:
		raise BaseException("No such function")
	return f.decompile(decompile_recursively=decompile_recursively)