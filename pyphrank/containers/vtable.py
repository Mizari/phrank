from __future__ import annotations

import idaapi
import idautils
import idc
import ida_struct

import pyphrank.settings as settings
import pyphrank.utils as utils
from pyphrank.containers.structure import Structure


class Vtable(Structure):
	REUSE_DELIM = "___V"
	def __init__(self, strucid):
		super().__init__(strucid)
		assert Vtable.is_strucid_vtable(self.strucid), "Structure is not vtable"

	@classmethod
	def get_vtable_at_address(cls, addr: int):
		addr_tif = utils.addr2tif(addr)
		if addr_tif is utils.UNKNOWN_TYPE:
			return None

		if not Vtable.is_vtable(addr_tif):
			return None

		vtbl_strucid = utils.tif2strucid(addr_tif)
		if vtbl_strucid == -1:
			utils.log_warn("failed to get strucid from vtbl tinfo")
			return None

		return cls(vtbl_strucid)

	def get_member_name(self, moffset:int) -> str:
		member_name = super().get_member_name(moffset)
		member_name = member_name.split(Vtable.REUSE_DELIM)[0]
		return member_name

	@staticmethod
	def is_vtable(vtbl_tif:idaapi.tinfo_t):
		if not vtbl_tif.is_struct():
			return None

		strucid = utils.tif2strucid(vtbl_tif)
		if strucid == -1:
			return False

		return Vtable.is_strucid_vtable(strucid)

	@staticmethod
	def is_strucid_vtable(strucid:int):
		if ida_struct.is_union(strucid):
			return False

		if ida_struct.get_struc_size(strucid) % settings.PTRSIZE != 0:
			return False

		# vtable has one data xref max
		# TODO or less? mb struct is vtable, but hasn't data object
		xrefs = [x.frm for x in idautils.XrefsTo(strucid)]
		if len(xrefs) > 1:
			return False

		# vtable_addr = xrefs[0]

		# TODO
		# check fields sizes
		# check every field is function start
		# check field names, field types
		# check xref only to addr
		return True

	@staticmethod
	def get_vtable_functions_at_addr(addr, minsize:int=2) -> list[int]:
		# TODO get list of ptrs inbetween xrefs
		# TODO get list of ptrs that are idaapi.is_loaded (idaapi.is_mapped?)
		# TODO get list of get_func_starts (mb try to expand it with add_func)

		# vtable should at least have on xref, vtable should be used somewhere
		if len([x for x in idautils.XrefsTo(addr)]) == 0:
			return []

		if settings.PTRSIZE == 8:
			read_pointer_func = idaapi.get_qword
		else:
			read_pointer_func = idaapi.get_dword

		ptrs = [read_pointer_func(addr)]
		addr += settings.PTRSIZE
		while True:
			# on next xref next vtable starts, vtables are used as pointers only
			if len([x for x in idautils.XrefsTo(addr)]) != 0:
				break

			ptr = read_pointer_func(addr)
			if not idaapi.is_loaded(ptr):
				break

			ptrs.append(ptr)
			addr += settings.PTRSIZE

		if len(ptrs) < minsize:
			return []

		addrs, not_addrs = utils.split_list(ptrs, lambda x: utils.get_func_start(x) == x)
		if len(addrs) == len(ptrs):
			return ptrs

		not_addrs = list(set(not_addrs))
		# create maximum one function
		if len(not_addrs) != 1 or len(addrs) == 0:
			return []

		potential_func = not_addrs[0]
		if idaapi.add_func(potential_func, idaapi.BADADDR):
			utils.log_warn(f"created new function at {hex(potential_func)}")
			return ptrs

		bad_idx = ptrs.index(potential_func)
		ptrs = ptrs[:bad_idx]
		if len(ptrs) < minsize:
			return []

		return ptrs