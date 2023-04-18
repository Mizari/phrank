from __future__ import annotations

import idc, idaapi

from phrank.util_ast import *
from phrank.util_tif import *
from phrank.util_func import *

def split_list(l:list, cond) -> tuple[list,list]:
	on_true = []
	on_false = []
	for i in l:
		if cond(i):
			on_true.append(i)
		else:
			on_false.append(i)
	return on_true, on_false

def get_next_available_strucname(strucname:str) -> str:
	while idaapi.get_struc_id(strucname) != idaapi.BADADDR:
		prefix, ctr = strucname.rsplit('_', 1)
		try:
			ctr = int(ctr)
			strucname = prefix + '_' + str(ctr + 1)
		except ValueError:
			pass
	return strucname

def size2dataflags(sz:int) -> int:
	df = {8: idaapi.FF_QWORD, 4: idaapi.FF_DWORD, 2: idaapi.FF_WORD, 1: idaapi.FF_BYTE}.get(sz, 0)
	return df | idaapi.FF_DATA

def iterate_segments():
	for segea in idautils.Segments():
		yield idc.get_segm_start(segea), idc.get_segm_end(segea)

def get_pointer_size() -> int:
	if idaapi.get_inf_structure().is_64bit():
		return 8
	elif idaapi.get_inf_structure().is_32bit():
		return 4
	else:
		return 2

def str2addr(s:str) -> int:
	base = 10
	if s.startswith("0x"): base = 16
	try:
		x = int(s, base)
	except:
		x = -1
	if idaapi.is_mapped(x):
		return x

	rv = idc.get_name_ea_simple(s)
	if rv == idaapi.BADADDR: rv = -1
	return rv