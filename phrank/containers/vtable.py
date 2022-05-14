import idaapi
import idautils
import idc
import ida_struct

import phrank.phrank_func as p_func
import phrank.phrank_util as p_util
import phrank.phrank_settings as p_settings
from phrank.containers.structure import Structure

class Vtable(Structure):
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
		addr = kwargs.get("addr", '')
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
			kwargs["name"] = t
			return self.__init_from_type_at_addr(*args, **kwargs)

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
				func_ptr_tif = p_util.get_voidptr_tinfo()
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
			if func_ptr_tif is None:
				continue
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

		bad_idx = ptrs.index(potential_func)
		ptrs = ptrs[:bad_idx]
		if len(ptrs) < minsize:
			return []

		return ptrs

	@staticmethod
	def calculate_vtable_size(addr):
		return len(Vtable.get_vtable_functions_at_addr(addr))


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

	def clear_created_vtables(self):
		self._created_vtables.clear()

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