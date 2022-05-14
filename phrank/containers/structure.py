import idaapi
import idc
import ida_struct
from phrank.containers.ida_struc_wrapper import IdaStrucWrapper, handle_addstrucmember_ret
import phrank.phrank_util as p_util


class Structure(IdaStrucWrapper):
	def __init__ (self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		if idaapi.is_union(self.strucid):
			raise BaseException("Error, should be struct")

	def member_names(self):
		for member_offset in self.member_offsets():
			yield idc.get_member_name(self.strucid, member_offset), hex(member_offset)

	def resize(self, size):
		# TODO ida_struct.expand_struc
		if self.get_size() == size: return

		if self.get_size() > size:
			self.unset_members(size, self.get_size() - size)
			return

		ptr_size = p_util.get_ptr_size()
		# self.size < size == True
		fill = size % ptr_size 
		size -= fill
		while self.get_size() != size:
			membername = 'field_' + hex(self.get_size())[2:]
			if membername[-1] == 'L': membername = membername[:-1]
			ret = idc.add_struc_member(self.strucid, membername, self.get_size(), p_util.size2dataflags(ptr_size), -1, ptr_size)

		for _ in range(fill):
			membername = 'field_' + hex(self.get_size())[2:]
			if membername[-1] == 'L': membername = membername[:-1]
			ret = idc.add_struc_member(self.strucid, membername, self.get_size(), p_util.size2dataflags(1), -1, 1)

	def is_offset_ok(self, offset, size):
		if offset + size <= self.get_size(): return True
		else: return False

	def set_member(self, name, offset, size):
		if not self.is_offset_ok(offset, size): raise BaseException("offset and size are too big")
		original_size = self.get_size()
		self.unset_members(offset, size)
		if self.get_size() < original_size - 1:
			self.resize(original_size - 1)

		ret = idc.add_struc_member(self.strucid, name, offset, p_util.size2dataflags(size), -1, size)
		handle_addstrucmember_ret(ret)
		if ret == idaapi.BADADDR: raise BaseException("Failed to append structure pointer")

	def set_struc(self, name, offset, struc):
		size = struc.get_size()
		if not self.is_offset_ok(offset, size): raise BaseException("offset and size are too big")
		self.unset_members(offset, size)
		ret = ida_struct.add_struc_member(self.strucid, name, offset, p_util.size2dataflags(1), -1, 1)
		handle_addstrucmember_ret(ret)
		idc.SetType(ida_struct.get_member_id(self.strucid, offset), struc.get_name())

	def set_strucptr(self, name, offset, struc):
		ptr_size = p_util.get_ptr_size()
		if not self.is_offset_ok(offset, ptr_size): raise BaseException("offset and size are too big")
		self.unset_members(offset, ptr_size)
		ret = ida_struct.add_struc_member(self.strucid, name, offset, p_util.size2dataflags(ptr_size), -1, ptr_size)
		handle_addstrucmember_ret(ret)
		idc.SetType(ida_struct.get_member_id(self.strucid, offset), struc.get_name() + "*")