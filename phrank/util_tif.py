from __future__ import annotations

import idaapi
import idc
from functools import cache as _cache


UNKNOWN_TYPE = idaapi.tinfo_t()


def str2strucid(s:str) -> int:
	if s.startswith("struct "):
		s = s[7:]

	rv = idaapi.get_struc_id(s)
	if rv != idaapi.BADADDR:
		return rv

	rv = idaapi.import_type(idaapi.get_idati(), -1, s)
	if rv == idaapi.BADNODE:
		return idaapi.BADADDR
	return rv

def tif2strucid(tif:idaapi.tinfo_t) -> int:
	while tif.is_ptr():
		tif = tif.get_pointed_object()

	if tif.is_array():
		tif = tif.get_array_element()

	if tif.is_struct():
		return str2strucid(str(tif))

	if (not tif.is_correct()) or tif.is_integral() or tif.is_void() or tif.is_func() or tif.is_enum() or tif.is_bool():
		return idaapi.BADADDR

	print("WARNING: unknown tinfo2strucid", tif)
	return idaapi.BADADDR


def addr2tif(addr:int) -> idaapi.tinfo_t:
	addr_type = idc.get_type(addr)
	if addr_type is None:
		return None

	return str2tif(addr_type)


@_cache
def str2tif(type_str:str) -> idaapi.tinfo_t|None:
	if type_str[-1] != ';': type_str = type_str + ';'

	tinfo = idaapi.tinfo_t()
	idaapi.parse_decl(tinfo, idaapi.get_idati(), type_str, 0)
	if not tinfo.is_correct():
		print("[*] WARNING: Failed to parse type: {}".format(type_str))
		return None
	return tinfo

def get_int_tinfo(size:int=1) -> idaapi.tinfo_t:
	char_tinfo = idaapi.tinfo_t()
	if size == 2:
		idaapi.parse_decl(char_tinfo, idaapi.get_idati(), "unsigned short;", 0)
	elif size == 4:
		idaapi.parse_decl(char_tinfo, idaapi.get_idati(), "unsigned int;", 0)
	else:
		idaapi.parse_decl(char_tinfo, idaapi.get_idati(), "unsigned char;", 0)
	assert char_tinfo.is_correct()
	return char_tinfo

# inner *__shifted(outer, offset)
def make_shifted_ptr(outer:idaapi.tinfo_t, inner:idaapi.tinfo_t, offset:int) -> idaapi.tinfo_t:
	shifted_tif = idaapi.tinfo_t()
	pi = idaapi.ptr_type_data_t()
	pi.taptr_bits = idaapi.TAPTR_SHIFTED
	pi.delta = offset
	pi.parent = outer
	pi.obj_type = inner
	shifted_tif.create_ptr(pi)
	return shifted_tif