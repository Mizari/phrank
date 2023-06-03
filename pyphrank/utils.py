from __future__ import annotations

import idc
import idaapi
import idautils

from pyphrank.util_ast import *
from pyphrank.util_tif import *
from pyphrank.util_func import *
from pyphrank.util_log import *

def split_list(list_to_split:list, cond) -> tuple[list,list]:
	on_true = []
	on_false = []
	for i in list_to_split:
		if cond(i):
			on_true.append(i)
		else:
			on_false.append(i)
	return on_true, on_false

def get_next_available_strucname(strucname:str, delimiter='__') -> str:
	while idaapi.get_struc_id(strucname) != idaapi.BADADDR:
		splitted = strucname.rsplit(delimiter, 1)
		if len(splitted) == 1:
			strucname = strucname + delimiter + '0'
			continue

		prefix, ctr = splitted
		if ctr.isdigit():
			ctr = str(int(ctr) + 1)
			strucname = prefix + delimiter + ctr
		else:
			strucname = strucname + delimiter + '0'

	return strucname

def get_next_available_membername(strucid:int, member_name:str, delimiter='__'):
	o = idc.get_member_offset(strucid, member_name)
	if o == -1 or o == idaapi.BADADDR:
		return member_name
	
	parts = member_name.split(delimiter)
	if len(parts) == 1:
		counter = 0
		base_name = member_name
	else:
		counter = int(parts[-1])
		base_name = "".join(parts[:-1])

	member_name = base_name + delimiter + str(counter)
	o = idc.get_member_offset(strucid, member_name)
	while o != idaapi.BADADDR and o != -1:
		counter += 1
		member_name = base_name + delimiter + str(counter)
		o = idc.get_member_offset(strucid, member_name)
	return member_name

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
	if s.startswith("0x"):
		base = 16
	try:
		x = int(s, base)
	except ValueError:
		x = -1
	if idaapi.is_mapped(x):
		return x

	rv = idc.get_name_ea_simple(s)
	if rv == idaapi.BADADDR:
		rv = -1
	return rv