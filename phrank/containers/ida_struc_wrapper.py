from __future__ import annotations

import idaapi
import idc
import ida_struct

import phrank.utils as utils


def handle_addstrucmember_ret(ret):
	if   ret == -1: errmsg = 'already has member with this name (bad name)'
	elif ret == -2: errmsg = 'already has member at this offset'
	elif ret == -3: errmsg = 'bad number of bytes or bad sizeof(type)'
	elif ret == -4: errmsg = 'bad typeid parameter'
	elif ret == -5: errmsg = 'bad struct id (the 1st argument)'
	elif ret == -6: errmsg = 'unions can\'t have variable sized members'
	elif ret == -7: errmsg = 'variable sized member should be the last member in the structure'
	elif ret == -8: errmsg = 'recursive structure nesting is forbidden'
	else: errmsg = "unknown error " + str(ret)
	if ret < 0: raise BaseException("Failed to AddStrucMember: " + errmsg)


class IdaStrucWrapper(object):
	def __init__(self, strucid):
		self.strucid = strucid

	@classmethod
	def get(cls, struc_info:str|idaapi.tinfo_t):
		if isinstance(struc_info, str):
			strucid = ida_struct.get_struc_id(struc_info)
		elif isinstance(struc_info, idaapi.tinfo_t):
			strucid = utils.tif2strucid(struc_info)
		else:
			raise TypeError("Invalid type for struc info")
		if strucid == idaapi.BADADDR:
			return None
		return cls(strucid)

	@property
	def name(self):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		return idc.get_struc_name(self.strucid, 0)

	@property
	def size(self):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		return ida_struct.get_struc_size(self.strucid)

	@property
	def tinfo(self):
		tif = idaapi.tinfo_t()
		assert tif.get_named_type(idaapi.get_idati(), self.name)
		return tif.copy()

	@property
	def ptr_tinfo(self):
		ptr_tinfo = self.tinfo
		ptr_tinfo.create_ptr(ptr_tinfo)
		return ptr_tinfo.copy()

	def is_union(self):
		return idaapi.is_union(self.strucid)

	def delete(self):
		if self.strucid == idaapi.BADADDR:
			return

		if idc.get_struc_idx(self.strucid) == idaapi.BADADDR:
			self.strucid = idaapi.BADADDR
			return

		idc.del_struc(self.strucid)
		self.strucid = idaapi.BADADDR

	def member_exists(self, name:str):
		if idc.get_member_offset(self.strucid, name) == -1:
			return False
		if idc.get_member_offset(self.strucid, name) == idaapi.BADADDR:
			return False
		return True

	def get_member_size(self, offset:int) -> int:
		return idc.get_member_size(self.strucid, offset)

	def get_member_name(self, offset:int) -> str:
		return idc.get_member_name(self.strucid, offset)

	def rename(self, newname:str):
		return idc.set_struc_name(self.strucid, newname)

	def set_member_comment(self, offset:int, cmt:str):
		rv = idc.set_member_cmt(self.strucid, offset, cmt, 0)
		if rv == 0:
			print("Failed to set member comment")
		return rv

	def get_member_comment(self, offset:int):
		return idc.get_member_cmt(self.strucid, offset, 0)

	def get_next_available_name(self, member_name:str, delimiter="___") -> str:
		o = idc.get_member_offset(self.strucid, member_name)
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
		o = idc.get_member_offset(self.strucid, member_name)
		while o != idaapi.BADADDR and o != -1:
			counter += 1
			member_name = base_name + delimiter + str(counter)
			o = idc.get_member_offset(self.strucid, member_name)
		return member_name

	def set_member_name(self, member_offset:int, member_name:str) -> int:
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		rv = idc.set_member_name(self.strucid, member_offset, member_name)
		if rv == 0:
			print("Failed to set member name " + str(member_name) + " in " + self.name + ' ' + hex(member_offset))
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
		if not self.is_offset_ok(offset, 1): raise BaseException("Offset too big " + hex(offset) + " in " + str(self.size))
		idc.del_struc_member(self.strucid, offset)

	def set_member_type(self, member_offset: int, member_type: idaapi.tinfo_t):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")

		#if member_type.get_size() != self.get_member_size(member_offset):
		#	self.unset_members(member_offset + self.get_member_size(member_offset), member_type.get_size() - self.get_member_size(member_offset))
		sptr = ida_struct.get_struc(self.strucid)
		mptr = ida_struct.get_member(sptr, member_offset)
		rv = ida_struct.set_member_tinfo(sptr, mptr, member_offset, member_type, ida_struct.SET_MEMTI_COMPATIBLE | ida_struct.SET_MEMTI_MAY_DESTROY)
		if rv == 0:
			print("[*] ERROR:", self.name, hex(member_offset), str(member_type))
			raise BaseException("Failed to change member type")
		return rv

	def add_member(self, member_offset:int, name=None):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		if name is None: name = "field_" + hex(member_offset)[2:]
		ret = idc.add_struc_member(self.strucid, name, member_offset, idaapi.FF_DATA | idaapi.FF_BYTE, -1, 1)
		handle_addstrucmember_ret(ret)

	def append_member(self, name:str, member_type:idaapi.tinfo_t, member_comment=None):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		size = member_type.get_size()
		ret = idc.add_struc_member(self.strucid, name, -1, utils.size2dataflags(size), -1, size)
		handle_addstrucmember_ret(ret)
		offset = self.size - size
		self.set_member_type(offset, member_type)
		if member_comment is not None:
			self.set_member_comment(offset, member_comment)