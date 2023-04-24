from __future__ import annotations

import idaapi
import idc
import ida_struct
import phrank.settings as settings
from phrank.containers.ida_struc_wrapper import IdaStrucWrapper, handle_addstrucmember_ret
import phrank.utils as utils


class Structure(IdaStrucWrapper):
	def __init__ (self, strucid):
		super().__init__(strucid)
		assert not self.is_union(), "Error, should be struct"

	@classmethod
	def create(cls, struc_name=None):
		strucid = idc.add_struc(idaapi.BADADDR, struc_name, False)
		return cls(strucid)

	def member_names(self):
		for member_offset in self.member_offsets():
			yield idc.get_member_name(self.strucid, member_offset), hex(member_offset)

	def maximize_size(self, min_size:int):
		if self.size < min_size:
			self.resize(min_size)

	def resize(self, new_size: int):
		current_size = self.size
		if current_size == new_size: return

		if current_size > new_size:
			self.unset_members(new_size, current_size - new_size)
			return

		self.expand(new_size - current_size)

	def expand(self, extra_size: int):
		current_size = self.size
		membername = 'field_' + hex(extra_size + current_size - 1)[2:]
		idc.add_struc_member(self.strucid, membername, current_size, utils.size2dataflags(1), -1, 1)
		idc.expand_struc(self.strucid, current_size, extra_size - 1, False)

	def is_offset_ok(self, offset:int, size:int):
		if offset + size <= self.size: return True
		else: return False

	def set_member(self, name:str, offset:int, size:int):
		if not self.is_offset_ok(offset, size): raise BaseException("offset and size are too big")
		original_size = self.size
		self.unset_members(offset, size)
		if self.size < original_size - 1:
			self.resize(original_size - 1)

		ret = idc.add_struc_member(self.strucid, name, offset, utils.size2dataflags(size), -1, size)
		handle_addstrucmember_ret(ret)
		if ret == idaapi.BADADDR: raise BaseException("Failed to append structure pointer")

	def set_struc(self, name:str, offset:int, struc):
		size = struc.size
		if not self.is_offset_ok(offset, size): raise BaseException("offset and size are too big")
		self.unset_members(offset, size)
		ret = ida_struct.add_struc_member(self.strucid, name, offset, utils.size2dataflags(1), -1, 1)
		handle_addstrucmember_ret(ret)
		idc.SetType(ida_struct.get_member_id(self.strucid, offset), struc.get_name())

	def set_strucptr(self, name:str, offset:int, struc):
		PTRSIZE = settings.PTRSIZE
		if not self.is_offset_ok(offset, PTRSIZE): raise BaseException("offset and size are too big")
		self.unset_members(offset, PTRSIZE)
		ret = ida_struct.add_struc_member(self.strucid, name, offset, utils.size2dataflags(PTRSIZE), -1, PTRSIZE)
		handle_addstrucmember_ret(ret)
		idc.SetType(ida_struct.get_member_id(self.strucid, offset), struc.get_name() + "*")

	def member_exists(self, offset:int) -> bool:
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")

		sptr = ida_struct.get_struc(self.strucid)
		mptr = ida_struct.get_member(sptr, offset)
		return mptr is not None

	def get_member_tinfo(self, member_offset:int) -> idaapi.tinfo_t|None:
		# TODO add ability to get member by offset or by name
		# get_member_by_fullname(fullname) -> member_t Get a member by its fully qualified name, "struct.field".
		# get_member_by_name(sptr, membername) -> member_t

		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		if idc.is_union(self.strucid):
			if member_offset >= idc.get_member_qty(self.strucid):
				print("fokk", self.name, idc.get_member_qty(self.strucid), hex(member_offset))
				raise BaseException("Offset too big")
		else:
			if member_offset >= self.size:
				raise BaseException("Offset too big")

		sptr = ida_struct.get_struc(self.strucid)
		mptr = ida_struct.get_member(sptr, member_offset)
		# member is unset
		if mptr is None:
			return None

		tif = idaapi.tinfo_t()
		# member has no type
		if not ida_struct.get_member_tinfo(tif, mptr):
			return None
		return tif

	def get_shifted_member_ptr_tinfo(self, offset:int) -> idaapi.tinfo_t:
		retval = idaapi.tinfo_t()

		class_tif = self.tinfo
		if offset == 0:
			assert retval.create_ptr(class_tif)

		else:
			# TODO check offset correctness
			# TODO looking into inner struct

			parent, parent_offset = self.get_parent_offset(offset)
			if parent is None:
				member_tinfo = self.get_member_tinfo(offset)
			else:
				if offset == parent_offset:
					member_tinfo = self.get_member_tinfo(offset)
				else:
					member_tinfo = parent.get_member_tinfo(offset - parent_offset)

			retval = utils.make_shifted_ptr(class_tif, member_tinfo, offset)

		return retval

	def get_next_member_offset(self, offset:int) -> int:
		if offset < 0 or offset > self.size:
			return -1

		sptr = ida_struct.get_struc(self.strucid)
		offset = ida_struct.get_struc_next_offset(sptr, offset)
		while offset != idaapi.BADADDR and not self.get_member_name(offset):
			offset = ida_struct.get_struc_next_offset(sptr, offset)

		if offset == idaapi.BADADDR:
			offset = -1
		return offset

	def get_member_start(self, offset:int) -> int:
		if offset < 0 or offset > self.size:
			return -1

		sptr = ida_struct.get_struc(self.strucid)
		member = ida_struct.get_member(sptr, offset)
		if member is None:
			return -1
		return member.soff

	def is_member_start(self, offset:int) -> bool:
		if offset < 0 or offset > self.size:
			return False

		return offset == self.get_member_start(offset)