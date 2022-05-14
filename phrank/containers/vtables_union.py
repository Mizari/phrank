import idaapi
import idc
import ida_struct

from phrank.containers.union import Union
from phrank.containers.vtable import Vtable

import phrank.phrank_util as p_util

class VtablesUnion(Union):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

	@staticmethod
	def is_vtables_union(vtbl_info):
		# TODO
		if isinstance(vtbl_info, idaapi.tinfo_t):
			if not vtbl_info.is_union():
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
				if not Vtable.is_vtable(mtif):
					return False

			return True

		else:
			raise BaseException("Unexpected vtable info type " + str(vtbl_info))

	def add_vtable(self, vtbl):
		# TODO check vtbl is vtable
		vname = vtbl.get_name()
		for member_offset in range(idc.get_member_qty(self.strucid)):
			mname = self.get_member_name(member_offset)
			if mname == vname:
				return

			mtif = self.get_member_tinfo(member_offset)
			if str(mtif) == vname + " *":
				return

		self.append_member(vname, p_util.get_ptr_size())
		tif = idaapi.tinfo_t()
		if not tif.get_named_type(idaapi.get_idati(), vname):
			raise BaseException("Failed to get tinfo from vtable struct")
		if not tif.create_ptr(tif):
			raise BaseException("Failed to get tinfo for vtable struct ptr")
		self.set_member_type(idc.get_member_qty(self.strucid) - 1, tif)