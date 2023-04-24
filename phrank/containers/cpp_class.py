import idaapi

import phrank.utils as utils

from phrank.containers.structure import Structure
from phrank.containers.vtables_union import VtablesUnion
from phrank.containers.vtable import Vtable
from phrank.analyzers.vtable_analyzer import VtableAnalyzer

class CppClass(Structure):
	def __init__(self, strucid):
		super().__init__(strucid)
		self._cdtors : set[CDtor] = set()
		self._vtables : dict[int, Vtable]= {}
		self._parents : dict[int, CppClass]= {}
		self._children : set[CppClass] = set()

	def add_cdtor(self, c):
		self._cdtors.add(c)

	def get_ctors(self):
		return [c for c in self._cdtors if c._is_ctor]

	def get_dtor(self):
		for c in self._cdtors:
			if c._is_dtor: return c
		return None

	def get_vtable(self, offset):
		return self._vtables.get(offset, None)

	def add_vtable(self, offset, vtbl):
		current_vtbl = self._vtables.setdefault(offset, vtbl)
		if current_vtbl != vtbl:
			print("[*] ERROR", self.name, hex(offset), idaapi.get_name(current_vtbl.get_ea()), idaapi.get_name(vtbl.get_ea()))
			raise BaseException("Already have vtbl at this offset")

	@staticmethod
	def is_cpp_class():
		# TODO
		return False

	def get_parent(self, offset):
		parent, _ = self.get_parent_offset(offset)
		return parent

	def get_parent_offset(self, offset):
		for parent_offset, parent in self._parents.items():
			if parent_offset <= offset and parent_offset + parent.size > offset:
				return parent, parent_offset
		return None, None

	def add_parent(self, offset, parent):
		assert isinstance(parent, CppClass), "Trying to add parent, that is not CppClass"

		current_parent = self.get_parent(offset)
		if current_parent is not None:
			assert current_parent == parent, "Already have parent at this offset, and it is a different one"
			return

		if parent.size + offset > self.size:
			print("ERROR:", self.name, idaapi.get_name(self.get_vtable(0).get_ea()), hex(offset), parent.name, hex(parent.size), idaapi.get_name(parent.get_vtable(0).get_ea()))
			raise BaseException("Cpp class size is changing on setting parent, this shouldnt happen (means size/inheritance analysis failed)")

		self._parents[offset] = parent

	def add_child(self, child):
		if child in self._children:
			return

		self._children.add(child)

	def set_vtable(self, offset, vtbl):
		parent, parent_offset = self.get_parent_offset(offset)
		if parent is not None:
			return parent.set_vtable(offset - parent_offset, vtbl)

		mtif = self.get_member_type(offset)
		if VtablesUnion.is_vtables_union(mtif):
			vu = VtablesUnion(name=str(mtif))
			vu.add_vtable(vtbl)
			return None

		mname = self.get_member_name(offset)
		# current vtbl --> union [current vtbl , vtbl]
		if mname == "vtable" or mname == "vtable_" + hex(offset)[2:]:
			member_vtbl = self.get_member_type(offset)
			member_vtbl = str(member_vtbl.get_pointed_object())
			member_vtbl = Structure.get(member_vtbl)

			vtbl_union_name = "vtables_union_0"
			vtbl_union_name = utils.get_next_available_strucname(vtbl_union_name)
			vu = VtablesUnion(name=vtbl_union_name)
			# need to add vtbl to union first, otherwise ida cant set member type, because its size is 0
			vu.add_vtable(vtbl)
			vu.add_vtable(member_vtbl)
			self.set_member_type(offset, vu.name)

			if offset == 0:
				vtbl_name = "vtables"
			else:
				vtbl_name = "vtables_" + hex(offset)[2:]
			self.set_member_name(offset, vtbl_name)
			return vu

		else:
			if offset == 0:
				mname = "vtable"
			else:
				mname = "vtable_" + hex(offset)[2:]
			self.set_member_name(offset, mname)
			self.set_member_type(offset, vtbl.get_name() + '*')
			return None

	def get_parent_vtable(self, offset):
		parent, parent_offset = self.get_parent_offset(offset)
		if parent is None:
			return None

		return parent.get_vtable(offset - parent_offset)


class CDtor(object):
	__slots__ = "_fea", "_is_ctor", "_is_dtor", "_cpp_class", "_vtbl_writes"
	def __init__(self, fea):
		self._fea : int = fea
		self._is_ctor : bool = False
		self._is_dtor : bool = False
		self._cpp_class : CppClass = None

		factory = VtableAnalyzer()
		self._vtbl_writes = {}
		for write in utils.ASTAnalysis(addr=fea).get_writes_into_var(0):
			int_write_val = write.get_int()
			if int_write_val is None:
				continue

			vtbl = factory.get_gvar_vtable(int_write_val)
			if vtbl is None:
				continue

			l = self._vtbl_writes.setdefault(write.get_offset(), [])
			l.append(vtbl)

	def get_main_vtables(self):
		main_vtables: dict[int, Vtable] = {}
		for offset, vtbls in self.vtbl_writes():
			if len(vtbls) == 1:  main_vtable = vtbls[0]
			elif self._is_ctor: main_vtable = vtbls[-1]
			elif self._is_dtor: main_vtable = vtbls[0]
			else:                main_vtable = None

			if main_vtable is None:
				continue

			# only analyze first vtbl write for doubling vtbls
			if main_vtable in main_vtables.values():
				continue

			main_vtables[offset] = main_vtable
		return main_vtables

	def is_unfinished(self):
		return not(self._is_ctor or self._is_dtor)

	def vtbl_writes(self, offset=None):
		for write_offset, vtbls in self._vtbl_writes.items():
			if offset is not None and write_offset != offset:
				continue

			yield write_offset, vtbls

	def get_vtbl_writes(self, offset):
		return self._vtbl_writes.get(offset, [])

	def get_ea(self):
		return self._fea

	def set_class(self, c):
		if self._cpp_class is not None and self._cpp_class != c:
			raise BaseException("Cdtor already has a class, and it is a different one")
		self._cpp_class = c