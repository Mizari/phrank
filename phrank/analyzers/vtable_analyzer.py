import idaapi
import phrank.util_aux as util_aux

from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.containers.vtable import Vtable

class VtableAnalyzer(TypeAnalyzer):
	def create_vtable_at_address(self, addr:int):
		vfcs = Vtable.get_vtable_functions_at_addr(addr)
		if len(vfcs) == 0:
			return None

		vtbl_name = "vtable_" + hex(addr)[2:]
		vtbl_name = util_aux.get_next_available_strucname(vtbl_name)
		vtbl = Vtable(struc_locator=vtbl_name)

		v_sz = len(vfcs)
		ptr_size = util_aux.get_ptr_size()
		vtbl.resize(v_sz * ptr_size)

		field_names = set()
		for i, func_addr in enumerate(vfcs):
			member_offset = i * ptr_size

			func_name = idaapi.get_name(func_addr)
			if func_name is None:
				print("Failed to get function name", hex(func_addr))

			func_ptr_tif = self.get_ptr_tinfo(func_addr)
			if func_ptr_tif is None:
				print("Failed to get function tinfo", hex(func_addr), func_name, "using void* instead")
				func_ptr_tif = util_aux.get_voidptr_tinfo()
			vtbl.set_member_type(member_offset, func_ptr_tif)
			vtbl.set_member_comment(member_offset, hex(func_addr))

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

			vtbl.set_member_name(member_offset, func_name)
			field_names.add(func_name)
		return vtbl

	def get_gvar_vtable(self, gvar_ea):
		gvar_tinfo = self.get_gvar_tinfo(gvar_ea)
		if gvar_tinfo is None:
			return None

		gvar_strucid = Vtable.get_existing_strucid(gvar_tinfo)
		if gvar_strucid == idaapi.BADADDR:
			return None

		if Vtable.is_vtable(gvar_strucid):
			return Vtable(gvar_ea, gvar_strucid)
		return None

	def analyze_gvar(self, gvar_ea):
		vtbl = self.gvar2tinfo.get(gvar_ea)
		if vtbl is not None:
			return vtbl

		# trying to initialize from type at address
		vtbl = Vtable.get_vtable_at_address(gvar_ea)
		if vtbl is not None:
			tif = vtbl.get_tinfo()
			self.gvar2tinfo[gvar_ea] = tif
			return tif

		vtbl = self.create_vtable_at_address(gvar_ea)
		if vtbl is None:
			return None

		self.new_types.append(vtbl.strucid)
		tif = vtbl.get_tinfo()
		self.gvar2tinfo[gvar_ea] = tif
		return tif

	def analyze_everything(self):
		for segstart, segend in util_aux.iterate_segments():
			self.analyze_segment(segstart, segend)

	def analyze_segment(self, segstart, segend):
		ptr_size = util_aux.get_ptr_size()
		while segstart < segend:
			vtbl = self.analyze_gvar(segstart)
			if vtbl is None:
				segstart += ptr_size
			else:
				segstart += vtbl.get_size()