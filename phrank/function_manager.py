import idaapi
import idc
import idautils
import re

import phrank.utils as utils

from phrank.ast_analyzer import ASTAnalyzer, ASTAnalysis
from phrank.cfunction_factory import CFunctionFactory

def get_funcname(func_ea: int):
	return idaapi.get_name(func_ea)

def is_movrax_ret(func_ea: int):
	# count blocks
	blocks = [b for b in idautils.Chunks(func_ea)]
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


class FunctionManager:
	def __init__(self, cfunc_factory=None):
		if cfunc_factory is None:
			cfunc_factory = CFunctionFactory()
		self.func_factory = cfunc_factory
		self.ast_analyzer = ASTAnalyzer()
		self.ast_analysis_cache = {}

	def get_ast_analysis(self, func_ea: int) -> ASTAnalysis:
		cached = self.ast_analysis_cache.get(func_ea)
		if cached is not None:
			return cached

		cfunc = self.get_cfunc(func_ea)
		if cfunc is None:
			analysis = ASTAnalysis()
		else:
			analysis = self.ast_analyzer.analyze_cfunc(cfunc)
		self.ast_analysis_cache[func_ea] = analysis
		return analysis

	def get_cfunc(self, func_ea):
		return self.func_factory.get_cfunc(func_ea)

	def get_func_details(self, func_ea: int):
		func_tinfo = self.get_tinfo(func_ea)
		if func_tinfo is None:
			return None

		func_details = idaapi.func_type_data_t()
		rv = func_tinfo.get_func_details(func_details)
		if not rv:
			print("Failed to get func details in", get_funcname(func_ea))
			return None
		return func_details

	def get_var_type(self, func_ea: int, var_id):
		cfunc = self.get_cfunc(func_ea)
		if cfunc is None:
			print("Failed to get variable type, because of decompilation failure in", get_funcname(func_ea))
			return None

		var = cfunc.lvars[var_id]
		return var.type()

	def set_var_type(self, func_ea: int, var_id, var_type):
		cfunc = self.get_cfunc(func_ea)
		if cfunc is None:
			print("Failed to change variable type, because of decompilation failure in", get_funcname(func_ea))
			return

		var = cfunc.lvars[var_id]
		# var.set_user_type()
		# var.set_final_lvar_type(var_type)

		info = idaapi.lvar_saved_info_t()
		info.ll = var
		info.type = var_type
		info.name = var.name
		rv = idaapi.modify_user_lvar_info(func_ea, idaapi.MLI_TYPE, info)
		assert rv, "Failed to modify lvar"

		self.func_factory.clear_cfunc(func_ea)

	def get_var(self, func_ea: int, var_idx):
		cfunc = self.get_cfunc(func_ea)
		if cfunc is None:
			return None
		return cfunc.lvars[var_idx]

	def get_arg_type(self, func_ea: int, arg_id):
		# XXX do not refactor this into one liner, 
		# XXX because ida will lose arg type somewhere along the way
		fdet = self.get_func_details(func_ea)
		if fdet is None:
			print("Failed to get func details in", get_funcname(func_ea))
			return

		return fdet[arg_id].type.copy()

	def set_arg_type(self, func_ea: int, arg_id, arg_type):
		if isinstance(arg_type, str):
			arg_type = utils.str2tif(arg_type)

		func_details = self.get_func_details(func_ea)
		if func_details is None:
			print("Failed to change argument type (no func details) in", get_funcname(func_ea))
			return

		func_details[arg_id].type = arg_type.copy()

		new_func_tinfo = idaapi.tinfo_t()
		rv = new_func_tinfo.create_func(func_details)
		assert rv, "Failed to create func tinfo from details"

		rv = idaapi.apply_tinfo(func_ea, new_func_tinfo, 0)
		assert rv, "Failed to apply new tinfo to function"

		self.func_factory.clear_cfunc(func_ea)

	def get_tinfo(self, func_ea: int):
		tif = idaapi.tinfo_t()

		cfunc = self.get_cfunc(func_ea)
		if cfunc is not None:
			cfunc.get_func_type(tif)
			if tif.is_correct():
				return tif

		if idaapi.get_tinfo(tif, func_ea) and tif.is_correct():
			return tif

		if is_movrax_ret(func_ea):
			tif = utils.get_voidfunc_tinfo()
			if tif.is_correct():
				return tif

		print("Failed to get tinfo for", hex(func_ea), get_funcname(func_ea))
		return None

	def get_ptr_tinfo(self, func_ea: int):
		tif = self.get_tinfo(func_ea)
		if tif is None:
			return None
		rv = tif.create_ptr(tif)
		if rv == False:
			print("Failed to change tinfo of", str(tif))
			return None
		return tif

	def get_nargs(self, func_ea: int):
		tif = self.get_tinfo(func_ea)
		if tif is None:
			return 0
		return tif.get_nargs()

	def get_lvars_counter(self, func_ea: int):
		cfunc = self.get_cfunc(func_ea)
		if cfunc is None: return 0

		counter = 0
		for lv in cfunc.get_lvars():
			if lv.name == '':
				continue
			counter += 1
		return counter