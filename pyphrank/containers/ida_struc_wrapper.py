from __future__ import annotations

import idaapi
import idc
import ida_struct

import pyphrank.utils as utils


class IdaStrucWrapper(object):
	add_struc_member_retvals = {
		-1: 'already has member with this name (bad name)',
		-2: 'already has member at this offset',
		-3: 'bad number of bytes or bad sizeof(type)',
		-4: 'bad typeid parameter',
		-5: 'bad struct id (the 1st argument)',
		-6: 'unions can\'t have variable sized members',
		-7: 'variable sized member should be the last member in the structure',
		-8: 'recursive structure nesting is forbidden',
	}

	@classmethod
	def handle_addstrucmember_ret(cls, ret):
		errmsg = cls.add_struc_member_retvals.get(ret, f"unknown error {str(ret)}")
		if ret < 0:
			utils.log_err(f"failed to AddStrucMember {errmsg}")

	def __init__(self, strucid):
		self.strucid = strucid

	@classmethod
	def get(cls, struc_info:str|idaapi.tinfo_t):
		if isinstance(struc_info, str):
			strucid = utils.str2strucid(struc_info)
		elif isinstance(struc_info, idaapi.tinfo_t):
			strucid = utils.tif2strucid(struc_info)
		else:
			raise TypeError("Invalid type for struc info")
		if strucid == -1:
			return None
		return cls(strucid)

	@property
	def name(self):
		return idc.get_struc_name(self.strucid, 0)

	@property
	def size(self):
		return ida_struct.get_struc_size(self.strucid)

	@property
	def tinfo(self):
		tif = idaapi.tinfo_t()
		assert tif.get_named_type(idaapi.get_idati(), self.name)
		return tif.copy()

	@property
	def ptr_tinfo(self):
		ptr_tinfo = idaapi.tinfo_t()
		ptr_tinfo.create_ptr(self.tinfo)
		return ptr_tinfo

	def is_union(self):
		return idaapi.is_union(self.strucid)

	def delete(self):
		if self.strucid == -1:
			return

		if idc.get_struc_idx(self.strucid) == idaapi.BADADDR:
			self.strucid = -1
			return

		idc.del_struc(self.strucid)
		self.strucid = -1

	def get_member_size(self, offset:int) -> int:
		return idc.get_member_size(self.strucid, offset)

	def get_member_name(self, offset:int) -> str:
		return idc.get_member_name(self.strucid, offset)

	def rename(self, newname:str):
		return idc.set_struc_name(self.strucid, newname)

	def set_member_comment(self, offset:int, cmt:str):
		rv = idc.set_member_cmt(self.strucid, offset, cmt, 0)
		if rv == 0:
			utils.log_warn(f"failed to set member comment in {self.name} at {hex(offset)}")
		return rv

	def get_member_comment(self, offset:int):
		return idc.get_member_cmt(self.strucid, offset, 0)

	def set_member_name(self, member_offset:int, member_name:str) -> int:
		rv = idc.set_member_name(self.strucid, member_offset, member_name)
		if rv == 0:
			utils.log_warn(f"failed to set member name {str(member_name)} in {self.name} at {hex(member_offset)}")
		return rv

	def member_offsets(self, skip_holes=True):
		sptr = ida_struct.get_struc(self.strucid)
		off = ida_struct.get_struc_first_offset(sptr)
		while off != idaapi.BADADDR:
			if skip_holes and not self.get_member_name(off):
				off = ida_struct.get_struc_next_offset(sptr, off)
			else:
				yield off
				off = ida_struct.get_struc_next_offset(sptr, off)

	def unset_members(self, offset_from:int, unset_size:int):
		unset_offsets = []
		for member_offset in self.member_offsets():
			if member_offset >= offset_from and member_offset < offset_from + unset_size:
				unset_offsets.append(member_offset)

		for mo in unset_offsets:
			self.del_member(mo)

	def del_member(self, offset:int):
		idc.del_struc_member(self.strucid, offset)

	def get_member_type(self, member_offset:int) -> idaapi.tinfo_t|None:
		# TODO add ability to get member by offset or by name
		# get_member_by_fullname(fullname) -> member_t Get a member by its fully qualified name, "struct.field".
		# get_member_by_name(sptr, membername) -> member_t

		if idc.is_union(self.strucid):
			if member_offset >= idc.get_member_qty(self.strucid):
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

	def set_member_type(self, member_offset: int, member_type: idaapi.tinfo_t):
		#if member_type.get_size() != self.get_member_size(member_offset):
		#	self.unset_members(member_offset + self.get_member_size(member_offset), member_type.get_size() - self.get_member_size(member_offset))
		sptr = ida_struct.get_struc(self.strucid)
		mptr = ida_struct.get_member(sptr, member_offset)
		rv = ida_struct.set_member_tinfo(sptr, mptr, member_offset, member_type, ida_struct.SET_MEMTI_COMPATIBLE | ida_struct.SET_MEMTI_MAY_DESTROY)
		if rv == 0:
			utils.log_err(f"failed to change member type in {self.name} to {str(member_type)} at {hex(member_offset)}")
			return rv
		return rv

	def add_member(self, member_offset:int, name=None) -> bool:
		if name is None:
			name = "field_" + hex(member_offset)[2:]
		ret = idc.add_struc_member(self.strucid, name, member_offset, idaapi.FF_DATA | idaapi.FF_BYTE, -1, 1)
		self.handle_addstrucmember_ret(ret)
		return ret >= 0

	def append_member(self, name:str, member_type:idaapi.tinfo_t, member_comment=None):
		size = member_type.get_size()
		ret = idc.add_struc_member(self.strucid, name, -1, utils.size2dataflags(size), -1, size)
		self.handle_addstrucmember_ret(ret)
		offset = self.size - size
		self.set_member_type(offset, member_type)
		if member_comment is not None:
			self.set_member_comment(offset, member_comment)