import idaapi
import idc
import idautils
import re

def is_func_start(addr):
	if addr == idaapi.BADADDR: return False
	return addr == get_func_start(addr)

def get_func_start(addr):
	func = idaapi.get_func(addr)
	if func is None:
		return idaapi.BADADDR
	return func.start_ea

def get_func_calls_to(fea):
	rv = filter(None, [get_func_start(x.frm) for x in idautils.XrefsTo(fea)])
	rv = filter(lambda x: x != idaapi.BADADDR, rv)
	return list(rv)

def get_func_calls_from(fea):
	return [x.to for r in idautils.FuncItems(fea) for x in idautils.XrefsFrom(r, 0) if x.type == idaapi.fl_CN or x.type == idaapi.fl_CF]

# finds connection in call-graph for selected functions
def got_path(fea, funcs):
	if isinstance(funcs, set):
		_funcs = funcs
	else:
		_funcs = set(funcs)

	calls_from_to = set()
	calls_from_to.update(get_func_calls_to(fea))
	calls_from_to.update(get_func_calls_from(fea))
	return len(_funcs & calls_from_to) != 0

def is_func_import(func_ea):
	for segea in idautils.Segments():
		if idc.get_segm_name(segea) != ".idata":
			continue

		segstart, segend = idc.get_segm_start(segea), idc.get_segm_end(segea)
		if func_ea >= segstart and func_ea < segend:
			return True

	return False

def iterate_all_functions():
	for segea in idautils.Segments():
		for funcea in idautils.Functions(segea, idc.get_segm_end(segea)):
			yield funcea

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

def decompile_function(func_ea):
	try:
		cfunc = idaapi.decompile(func_ea)
		str(cfunc)
		return cfunc
	except idaapi.DecompilationFailure:
		print("failed to decompile", hex(func_ea), idaapi.get_name(func_ea))
		return None