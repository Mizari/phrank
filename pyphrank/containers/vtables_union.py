from __future__ import annotations

import idaapi
import idc
import ida_struct

from pyphrank.containers.union import Union
from pyphrank.containers.vtable import Vtable
import pyphrank.utils as utils


class VtablesUnion(Union):
	@staticmethod
	def is_vtables_union(vtbl_info:idaapi.tinfo_t|str|int) -> bool:
		# TODO
		if isinstance(vtbl_info, idaapi.tinfo_t):
			if not vtbl_info.is_union(): # type: ignore
				return False
			return VtablesUnion.is_vtables_union(str(vtbl_info))

		elif vtbl_info is None:
			return False

		elif isinstance(vtbl_info, str):
			return VtablesUnion.is_vtables_union(idc.get_struc_id(vtbl_info))

		elif isinstance(vtbl_info, int):
			if not idc.is_union(vtbl_info):
				return False

			sptr = ida_struct.get_struc(vtbl_info)
			for member_offset in range(idc.get_member_qty(vtbl_info)):
				mptr = ida_struct.get_member(sptr, member_offset)
				mtif = idaapi.tinfo_t()
				# member has no type
				if not ida_struct.get_member_tinfo(mtif, mptr):
					return False
				
				if not mtif.is_ptr():
					return False

				mtif = mtif.get_pointed_object()
				strucid = utils.tif2strucid(mtif)
				if not Vtable.is_strucid_vtable(strucid):
					return False

			return True

		else:
			raise BaseException("Unexpected vtable info type " + str(vtbl_info))

	def add_vtable(self, vtbl:Vtable):
		# TODO check vtbl is vtable
		vname = vtbl.name
		for member_offset in range(idc.get_member_qty(self.strucid)):
			mname = self.get_member_name(member_offset)
			if mname == vname:
				return

			mtif = self.get_member_type(member_offset)
			if str(mtif) == vname + " *":
				return

		tif = vtbl.ptr_tinfo
		self.append_member(vname, tif)