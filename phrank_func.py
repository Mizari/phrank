import idc
import idaapi
import phrank_util as p_util
from typing import Optional

class FuncWrapper(object):
	__slots__ = "__func", "__cfunc"
	_instances = {}

	@staticmethod
	def clear_cache():
		FuncWrapper._instances.clear()

	@staticmethod
	def __get_func(*args, **kwargs):
		addr = kwargs.get("addr", None)
		if addr is None:
			funcname = kwargs.get("name", None)
			if funcname is None:
				raise BaseException("No addr and no name are given, need one from them")
			addr = idc.get_name_ea_simple(funcname)

		func = idaapi.get_func(addr)
		return func

	@staticmethod
	def get_start_ea(*args, **kwargs):
		func = FuncWrapper.__get_func(*args, **kwargs)
		if func is None:
			return idaapi.BADADDR
		return func.start_ea

	def __new__(cls, *args, **kwargs):
		addr = FuncWrapper.get_start_ea(*args, **kwargs)
		if addr == idaapi.BADADDR:
			if kwargs.get("noraise"):
				return None
			print("[*] ERROR", "func args", args, kwargs)
			raise BaseException("Failed to get function start")

		o = FuncWrapper._instances.get(addr, None)
		if o is None:
			o = super().__new__(cls)
		return o

	def __init__(self, *args, **kwargs):
		func = FuncWrapper.__get_func(*args, **kwargs)
		if func is None:
			raise BaseException("Failed to get function start")

		o = FuncWrapper._instances.get(func.start_ea, None)
		# skip init if object was already inited
		if o:
			return
		FuncWrapper._instances[func.start_ea] = self

		self.__func : idaapi.func_t = func
		self.__cfunc : Optional[idaapi.cfunptr_t] = None

	def get_func_details(self):
		func_tinfo = self.get_tinfo()
		func_details = idaapi.func_type_data_t()
		rv = func_tinfo.get_func_details(func_details)
		assert rv, "Failed to get func details"
		return func_details

	def set_argvar_type(self, arg, var_type):
		var = self.get_cfunc().arguments[arg]
		# var.set_user_type()
		# var.set_final_lvar_type(var_type)

		ll = idaapi.lvar_locator_t()
		rv = idaapi.locate_lvar(ll, self.__func.start_ea, var.name)
		assert rv, "Failed to locate lvar"

		info = idaapi.lvar_saved_info_t()
		info.ll = ll
		info.type = var_type
		info.name = var.name
		rv = idaapi.modify_user_lvar_info(self.__func.start_ea, idaapi.MLI_TYPE, info)
		assert rv, "Failed to modify lvar"

		self.__cfunc = None

	def get_arg_type(self, arg_id):
		# XXX do not refactor this into one liner, 
		# XXX because ida will lose arg type somewhere along the way
		fdet = self.get_func_details()
		return fdet[arg_id].type.copy()

	def set_arg_type(self, arg_id, arg_type):
		func_details = self.get_func_details()
		func_details[arg_id].type = arg_type.copy()

		new_func_tinfo = idaapi.tinfo_t()
		rv = new_func_tinfo.create_func(func_details)
		assert rv, "Failed to create func tinfo from details"

		rv = idaapi.apply_tinfo(self.__func.start_ea, new_func_tinfo, 0)
		assert rv, "Failed to apply new tinfo to function"

		self.__cfunc = None

	def get_start(self):
		return self.__func.start_ea

	def get_tinfo(self):
		tif = idaapi.tinfo_t()
		if not idaapi.get_tinfo(tif, self.__func.start_ea):
			# it works
			_ = self.get_cfunc()
			if not idaapi.get_tinfo(tif, self.__func.start_ea):
				raise BaseException("Failed to get tinfo for " + idaapi.get_name(self.__func.start_ea))
		return tif

	def get_ptr_tinfo(self):
		tif = self.get_tinfo()
		rv = tif.create_ptr(tif)
		if rv == False:
			raise BaseException("Failed to change tinfo")
		return tif

	def get_cfunc(self):
		if self.__cfunc is None:
			# first try creating all cfuncs for calls from here
			# this way args for called functions will be generated
			for xr in p_util.get_func_calls_from(self.get_start()):
				try:
					_ = get_func_cfunc(xr)
				except idaapi.DecompilationFailure:
					pass

			self.__cfunc = idaapi.decompile(self.__func.start_ea)
			str(self.__cfunc)
		return self.__cfunc

	def get_nargs(self):
		return self.get_tinfo().get_nargs()

def get_func_tinfo(func_addr):
	f = FuncWrapper(addr=func_addr, noraise=True)
	if f is None:
		return None
	return f.get_tinfo()

def get_func_nargs(func_addr):
	ftif = get_func_tinfo(func_addr)
	return ftif.get_nargs()

def get_func_ptr_tinfo(func_addr):
	f = FuncWrapper(addr=func_addr, noraise=True)
	if f is None:
		return None
	
	return f.get_ptr_tinfo()

def get_func_start(func_addr):
	return FuncWrapper.get_func_start(addr=func_addr)

def get_func_cfunc(addr):
	f = FuncWrapper(addr=addr, noraise=True)
	if f is None:
		return None
	return f.get_cfunc()

def is_function_start(func_addr):
	return func_addr == get_func_start(func_addr)

def set_func_arg_type(addr, arg_id, arg_type):
	f = FuncWrapper(addr=addr, noraise=True)
	if f is None:
		raise BaseException("No such function")
	return f.set_arg_type(arg_id, arg_type)

def get_func_arg_type(addr, arg_id):
	f = FuncWrapper(addr=addr, noraise=True)
	if f is None:
		raise BaseException("No such function")
	return f.get_arg_type(arg_id)

def set_func_argvar_type(addr, arg_id, var_type):
	f = FuncWrapper(addr=addr, noraise=True)
	if f is None:
		raise BaseException("No such function")
	return f.set_argvar_type(arg_id, var_type)