import idc
import idaapi
import phrank_settings
import phrank_util as p_util
from typing import Optional


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
		if self.__is_decompiled:
			return self.__cfunc
		
		self.decompile()
		return self.__cfunc

	def decompile(self):
		self.__is_decompiled = True

		for prefix in phrank_settings.FUNCTION_PREFIXES_DECOMPILATION_SKIP_LIST:
			if self.get_name().startswith(prefix):
				return None

		if phrank_settings.DECOMPILE_RECURSIVELY:
			for subcall in p_util.get_func_calls_from(self.get_start()):
				_ = get_func_cfunc(subcall)

		self.__cfunc = idaapi.decompile(self.get_start())
		str(self.__cfunc)
		return self.__cfunc

	def clear_decompile(self):
		self.__is_decompiled = False
		self.__cfunc = None

	def get_nargs(self):
		return self.get_tinfo().get_nargs()

def get_func_tinfo(func_addr):
	f = FuncWrapper.create(addr=func_addr, noraise=True)
	if f is None:
		return None
	return f.get_tinfo()

def get_func_nargs(func_addr):
	ftif = get_func_tinfo(func_addr)
	return ftif.get_nargs()

def get_func_ptr_tinfo(func_addr):
	f = FuncWrapper.create(addr=func_addr, noraise=True)
	if f is None:
		return None
	
	return f.get_ptr_tinfo()

def get_func_cfunc(addr):
	f = FuncWrapper.create(addr=addr, noraise=True)
	if f is None:
		return None
	return f.get_cfunc()

def is_function_start(func_addr):
	return func_addr == get_func_start(func_addr)

def set_func_arg_type(addr, arg_id, arg_type):
	f = FuncWrapper.create(addr=addr, noraise=True)
	if f is None:
		raise BaseException("No such function")
	return f.set_arg_type(arg_id, arg_type)

def get_func_arg_type(addr, arg_id):
	f = FuncWrapper.create(addr=addr, noraise=True)
	if f is None:
		raise BaseException("No such function")
	return f.get_arg_type(arg_id)

def set_func_argvar_type(addr, arg_id, var_type):
	f = FuncWrapper.create(addr=addr, noraise=True)
	if f is None:
		raise BaseException("No such function")
	return f.set_argvar_type(arg_id, var_type)