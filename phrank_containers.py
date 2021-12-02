import idaapi
import idc
import idautils
import ida_struct

import phrank_func as p_func
import phrank_util as p_util
import phrank_settings as p_settings



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


class IdaStruc(object):
	__slots__ = "strucid"
	def __init__(self, *args, **kwargs):
		self.strucid : int = idaapi.BADADDR

		strucid = kwargs.get("strucid", None)
		name = kwargs.get("name", None)
		is_union = kwargs.get("is_union", False)

		if strucid is not None:
			if idc.get_struc_idx(self.strucid) == idaapi.BADADDR:
				raise BaseException("Invalid strucid")
			self.strucid = strucid

		else:
			# check existing
			if name is not None:
				self.strucid = idc.get_struc_id(name)
	
			if self.strucid == idaapi.BADADDR:
				self.strucid = idc.add_struc(idaapi.BADADDR, name, is_union)

	def delete(self):
		if self.strucid == idaapi.BADADDR:
			return

		if idc.get_struc_idx(self.strucid) == idaapi.BADADDR:
			self.strucid = idaapi.BADADDR
			return

		idc.del_struc(self.strucid)
		self.strucid = idaapi.BADADDR

	def member_exists(self, name):
		if idc.get_member_offset(self.strucid, name) == -1:
			return False
		if idc.get_member_offset(self.strucid, name) == idaapi.BADADDR:
			return False
		return True

	def get_name(self):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		return idc.get_struc_name(self.strucid, 0)

	def get_member_size(self, offset):
		return idc.get_member_size(self.strucid, offset)

	def get_member_name(self, offset):
		return idc.get_member_name(self.strucid, offset)

	def rename(self, newname):
		return idc.set_struc_name(self.strucid, newname)

	def get_strucid(self):
		return self.strucid

	def get_size(self):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		return ida_struct.get_struc_size(self.strucid)

	def set_member_comment(self, offset, cmt):
		rv = idc.set_member_cmt(self.strucid, offset, cmt, 0)
		if rv == 0:
			print("Failed to set member comment")
		return rv

	def set_member_name(self, member_offset, member_name):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		rv = idc.set_member_name(self.strucid, member_offset, member_name)
		if rv == 0:
			print("Failed to set member name " + str(member_name) + " in " + self.get_name() + ' ' + hex(member_offset))
		return rv
	
	def get_member_tinfo(self, member_offset):
		# TODO add ability to get member by offset or by name
		# get_member_by_fullname(fullname) -> member_t Get a member by its fully qualified name, "struct.field".
		# get_member_by_name(sptr, membername) -> member_t

		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		if idc.is_union(self.strucid):
			if member_offset >= idc.get_member_qty(self.strucid):
				print("fokk", self.get_name(), idc.get_member_qty(self.strucid), hex(member_offset))
				raise BaseException("Offset too big")
		else:
			if member_offset >= self.get_size():
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
	
	def member_offsets(self):
		member_offset = idc.get_first_member(self.strucid)
		while member_offset != idaapi.BADADDR:
			if member_offset >= self.get_size(): 
				return

			yield member_offset
			member_offset = idc.get_next_offset(self.strucid, member_offset)

	def unset_members(self, offset_from, unset_size):
		unset_offsets = []
		for member_offset in self.member_offsets():
			if member_offset >= offset_from and member_offset < offset_from + unset_size:
				unset_offsets.append(member_offset)

		for mo in unset_offsets:
			self.del_member(mo)

	def del_member(self, offset):
		if not self.is_offset_ok(offset, 1): raise BaseException("Offset too big " + hex(offset) + " in " + str(self.get_size()))
		idc.del_struc_member(self.strucid, offset)

	def set_member_type(self, member_offset, member_type):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")

		if isinstance(member_type, str):
			if member_type[-1] != ';': member_type = member_type + ';'
			tif = idaapi.tinfo_t()
			idaapi.parse_decl(tif, idaapi.get_idati(), member_type, 0)
			if not tif.is_correct():
				raise BaseException("Failed to get type from string")
			return self.set_member_type(member_offset, tif)

		elif isinstance(member_type, idaapi.tinfo_t):
			#if member_type.get_size() != self.get_member_size(member_offset):
			#	self.unset_members(member_offset + self.get_member_size(member_offset), member_type.get_size() - self.get_member_size(member_offset))
			sptr = ida_struct.get_struc(self.strucid)
			mptr = ida_struct.get_member(sptr, member_offset)
			rv = ida_struct.set_member_tinfo(sptr, mptr, member_offset, member_type, ida_struct.SET_MEMTI_COMPATIBLE | ida_struct.SET_MEMTI_MAY_DESTROY)
			if rv == 0:
				print("[*] ERROR:", self.get_name(), hex(member_offset), str(member_type))
				raise BaseException("Failed to change member type")
			return rv

		else:
			raise BaseException("Invalid type(member type)")

	def add_member(self, member_offset, name):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		# ret = ida_struct.add_struc_member(self.strucid, name, 0, idaapi.FF_DATA | idaapi.FF_DWORD, -1, putil.get_ptr_size())
		ret = idc.add_struc_member(self.strucid, name, member_offset, idaapi.FF_DATA | idaapi.FF_DWORD, -1, p_util.get_ptr_size())
		handle_addstrucmember_ret(ret)

	def append_member(self, name, size):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		ret = idc.add_struc_member(self.strucid, name, -1, p_util.size2dataflags(size), -1, size)
		handle_addstrucmember_ret(ret)

	def append_struc(self, name, struc):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		ret = idc.add_struc_member(self.strucid, name, -1, p_util.size2dataflags(1), -1, 1)
		handle_addstrucmember_ret(ret)
		idc.SetType(idc.get_member_id(self.strucid, self.get_size()), struc.get_name())

	def append_strucptr(self, name, struc):
		if self.strucid == idaapi.BADADDR: raise BaseException("Invalid strucid")
		ret = idc.add_struc_member(self.strucid, name, -1, p_util.size2dataflags(1), -1, 1)
		handle_addstrucmember_ret(ret)
		idc.SetType(idc.get_member_id(self.strucid, self.get_size()), struc.get_name() + "*")


class Union(IdaStruc):
	def __init__(self, *args, **kwargs):
		super().__init__(is_union=True, *args, **kwargs)
		if not idaapi.is_union(self.strucid):
			raise BaseException("Error, should be union " + self.get_name())

	@staticmethod
	def is_union():
		# TODO
		return


class Struct(IdaStruc):
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


class Vtable(Struct):
	__slots__ = "_v_ea"
	REUSE_DELIM = "___V"
	def __init_existing(self, *args, **kwargs):
		# create vtable from existing one by name/strucid
		super().__init__(*args, **kwargs)
		if not Vtable.is_vtable(self.strucid):
			raise BaseException("Structure is not vtable")

		xrefs = [x.frm for x in idautils.XrefsTo(self.strucid)]
		if len(xrefs) != 0:
			self._v_ea = xrefs[0]

	def __init_from_type_at_addr(self, *args, **kwargs):
		addr = args.get("addr", '')
		super().__init__(*args, **kwargs)
		self._v_ea = addr
		# TODO check that this structure actually represents vtable at addr
		return

	def __init__(self, *args, **kwargs):
		self._v_ea : int = idaapi.BADADDR

		addr = kwargs.get("addr", None)
		if addr is None:
			return self.__init_existing(*args, **kwargs)

		t = idc.get_type(addr)
		if Vtable.is_vtable(t):
			return self.__init_from_type_at_addr(name=t, *args, **kwargs)

		return self.__init_new(*args, **kwargs)
	
	def __init_new(self, *args, **kwargs):
		# create new strucid
		# TODO better name generation for new vtable structure
		# TODO if setting type at vtable address, then set name too
		# TODO can vtable have <2 xrefs to addr? at least 1 ctor and 1 dtor should access vtable, no?
		super().__init__(*args, **kwargs)
		self._v_ea = kwargs.get("addr", None)

		vtbl_funcs = kwargs.get("vtbl_funcs", None)
		if vtbl_funcs is None:
			vtbl_funcs = Vtable.get_vtable_functions_at_addr(self._v_ea)
		v_sz = len(vtbl_funcs)
		ptr_size = p_util.get_ptr_size()
		self.resize(v_sz * ptr_size)

		field_names = set()
		for i, func_addr in enumerate(vtbl_funcs):
			member_offset = i * ptr_size

			func_name = idaapi.get_name(func_addr)
			if func_name is None:
				print("Failed to get function name", hex(func_addr))

			func_ptr_tif = p_func.get_func_ptr_tinfo(func_addr)
			if func_ptr_tif is None:
				print("Failed to get function tinfo", hex(func_addr), func_name, "using void* instead")
				func_ptr_tif = p_util.voidptr_tinfo.copy()
			self.set_member_type(member_offset, func_ptr_tif)
			self.set_member_comment(member_offset, hex(func_addr))

			if func_name is None:
				continue

			if func_name in field_names:
				parts = func_name.split(Vtable.REUSE_DELIM)
				if len(parts) == 1:
					x = 0
				else:
					x = int(parts[1])
				while func_name + Vtable.REUSE_DELIM + str(x) in field_names:
					x += 1
				func_name = func_name + Vtable.REUSE_DELIM + str(x)

			self.set_member_name(member_offset, func_name)
			field_names.add(func_name)

		set_type = kwargs.get("set_type", None)
		if set_type is None:
			set_type = p_settings.SHOULD_SET_VTABLE_TYPES
		if set_type:
			self.set_data()

	def update_func_types(self):
		for member_offset in self.member_offsets():
			member_name = self.get_member_name(member_offset)
			func_addr = idc.get_name_ea_simple(member_name)
			func_ptr_tif = p_func.get_func_ptr_tinfo(func_addr)
			self.set_member_type(member_offset, func_ptr_tif)

	def get_member_name(self, moffset):
		member_name = super().get_member_name(moffset)
		member_name = member_name.split(Vtable.REUSE_DELIM)[0]
		return member_name

	def get_ea(self):
		return self._v_ea

	def set_data(self):
		# TODO set name too
		idc.SetType(self._v_ea, self.get_name())

	@staticmethod
	def is_vtable(vinfo):
		if vinfo is None:
			return False
		
		if isinstance(vinfo, idaapi.tinfo_t):
			vinfo = str(vinfo)

		if isinstance(vinfo, str):
			vinfo = ida_struct.get_struc_id(vinfo)

		if not isinstance(vinfo, int):
			raise BaseException("Unexpected vinfo type " + type(vinfo) + ' ' + str(vinfo))

		if vinfo == idaapi.BADADDR:
			return False
		
		if ida_struct.is_union(vinfo):
			return False

		if ida_struct.get_struc_size(vinfo) % p_util.get_ptr_size() != 0:
			return False

		# vtable has one data xref max
		# TODO or less? mb struct is vtable, but hasn't data object
		xrefs = [x.frm for x in idautils.XrefsTo(vinfo)]
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
	def get_vtable_functions_at_addr(addr, minsize=1):
		# TODO get list of ptrs inbetween xrefs
		# TODO get list of ptrs that are idaapi.is_loaded (idaapi.is_mapped?)
		# TODO get list of get_func_starts (mb try to expand it with add_func)

		# vtable should at least have on xref, vtable should be used somewhere
		if len([x for x in idautils.XrefsTo(addr)]) == 0:
			return []

		ptr_size = p_util.get_ptr_size()
		ptrs = [p_util.read_ptr(addr)]
		addr += ptr_size
		while True:
			# on next xref next vtable starts, vtables are used as pointers only
			if len([x for x in idautils.XrefsTo(addr)]) != 0:
				break

			ptr = p_util.read_ptr(addr)
			if not idaapi.is_loaded(ptr):
				break

			ptrs.append(ptr)
			addr += ptr_size

		if len(ptrs) < minsize:
			return []

		addrs, not_addrs = p_util.split_list(ptrs, lambda x: p_util.get_func_start(x) == x)
		if len(addrs) == len(ptrs):
			return ptrs

		not_addrs = set(not_addrs)
		# create maximum one function
		if len(not_addrs) != 1 or len(addrs) == 0:
			return []

		potential_func = not_addrs.pop()
		if idaapi.add_func(potential_func, idaapi.BADADDR):
			print("[*] WARNING", "created new function at", hex(potential_func))
			return ptrs

		return []

	@staticmethod
	def calculate_vtable_size(addr):
		return len(Vtable.get_vtable_functions_at_addr(addr))


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


class VtableFactory(object):
	__slots__ = "_created_vtables", "_min_vtbl_size"
	__instance = None
	def __new__(cls, *args, **kwargs):
		if VtableFactory.__instance is not None:
			return VtableFactory.__instance

		return super().__new__(cls, *args, **kwargs)

	def __init__(self):
		if VtableFactory.__instance is not None:
			return

		super().__init__()
		VtableFactory.__instance = self

		self._created_vtables : dict[int, Vtable] = {}
		self._min_vtbl_size = 2

	def get_vtable(self, vtable_ea):
		return self._created_vtables.get(vtable_ea, None)

	def get_vtables(self):
		return list(self._created_vtables.values())

	def make_vtable(self, addr):
		vtbl = self._created_vtables.get(addr, None)
		if vtbl is not None:
			return vtbl
		
		vfcs = self.get_candidate_at(addr)
		if vfcs is None:
			return None

		return self.create_vtable(addr=addr, vtbl_vuncs=vfcs)

	def get_new_vtbl_name(self):
		vtbl_name = "vtable_" + str(len(self._created_vtables))
		vtbl_name = p_util.get_next_available_strucname(vtbl_name)
		return vtbl_name

	def new_vtable(self, *args, **kwargs):
		return Vtable(*args, **kwargs)

	def create_vtable(self, *args, **kwargs):
		vtbl_name = self.get_new_vtbl_name()
		kwargs["name"] = vtbl_name
		vtbl = self.new_vtable(*args, **kwargs)
		vtbl_ea = vtbl.get_ea()
		if vtbl_ea is not None:
			self._created_vtables[vtbl_ea] = vtbl
		else:
			print("[*] WARNING", "created vtable without address", vtbl.get_name())
		return vtbl

	def find_all_candidates(self):
		for segea in idautils.Segments():
			segstart = idc.get_segm_start(segea)
			segend = idc.get_segm_end(segea)
			yield from self.find_candidates_at(segstart, segend)

	def get_candidate_at(self, addr):
		vfcs = Vtable.get_vtable_functions_at_addr(addr, minsize=self._min_vtbl_size)
		if len(vfcs) == 0:
			return None

		return vfcs

	def find_candidates_at(self, ea_start, ea_end):
		ptr_size = p_util.get_ptr_size()
		it_ea = ea_start
		while it_ea < ea_end:
			vfcs = self.get_candidate_at(it_ea)
			if vfcs is None:
				it_ea += ptr_size
				continue
			yield it_ea, vfcs
			it_ea += len(vfcs) * ptr_size

	def create_all_vtables(self):
		for vtbl_ea, vtbl_funcs in self.find_all_candidates():
			vtbl = self.create_vtable(addr=vtbl_ea, vtbl_vuncs=vtbl_funcs)