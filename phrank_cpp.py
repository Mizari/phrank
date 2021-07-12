import idaapi
import idautils
import idc
import phrank_func as p_func
import phrank_util as p_util
import phrank_hexrays as p_hrays
import phrank_containers as p_cont

from typing import Optional

class CppVtable(p_cont.Vtable):
	__slots__ = "_vdtor", "_callers", "_vdtor_calls", "_cpp_class", "_cpp_class_offset"
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self._vdtor : Optional[int] = None
		self._callers : Optional[dict[int, int]] = None
		self._vdtor_calls : Optional[set[int]] = None
		self._cpp_class = None
		self._cpp_class_offset = idaapi.BADSIZE

	def make_callers(self) -> None:
		callers = [p_util.get_func_start(x.frm) for x in idautils.XrefsTo(self.get_ea())]
		callers = list(filter(lambda x: x != idaapi.BADADDR, callers))

		self._callers = {}
		for c in callers:
			writes = p_hrays.ThisUsesVisitor(addr=c).get_int_writes(val=self.get_ea())
			if len(writes) > 1:
				print("[*] WARNING:", "Vtable is written several times to this ptr", idaapi.get_name(c), idaapi.get_name(self.get_ea()))

			if len(writes) == 0:
				print("[*] WARNING:", "Vtable is not used as write to this ptr", idaapi.get_name(c), idaapi.get_name(self.get_ea()))
				continue

			write_offset = writes[0].get_offset()
			l = self._callers.get(write_offset, None)
			if l is None:
				l = []
				self._callers[write_offset] = l
			l.append(c)

		self._cpp_class = None
		self._cpp_class_offset = None

	def set_class_offset(self, cpp_cls, offset: int) -> None:
		assert isinstance(cpp_cls, CppClass)

		if self._cpp_class is not None:
			if self._cpp_class != cpp_cls or self._cpp_class_offset != offset:
				print("[*] ERROR:", hex(offset), idaapi.get_name(self.get_ea()))
				raise BaseException("Setting class in vtable, that already has a class")
			return

		self._cpp_class = cpp_cls
		self._cpp_class_offset = offset

	def get_class(self):
		return self._cpp_class

	def get_virtual_dtor(self) -> int:
		if self._vdtor is not None:
			return self._vdtor

		def is_vdtor(func_addr, vtbl_ea):
			if p_func.get_func_nargs(func_addr) != 2:
				return False

			tuv = p_hrays.ThisUsesVisitor(addr=func_addr)
			writes = tuv.get_int_writes(offset=0, val=vtbl_ea)
			if len(writes) == 0:
				return False

			return True

		vdtor = idaapi.get_dword(self.get_ea())
		if is_vdtor(vdtor, self.get_ea()):
			self._vdtor = vdtor
		else:
			self._vdtor = idaapi.BADADDR

		return self._vdtor

	def get_virtual_dtor_calls(self) -> set[int]:
		if self._vdtor_calls is None:
			self._vdtor_calls = set()
			if self.get_virtual_dtor() is not None:
				self._vdtor_calls.update(p_util.get_func_calls_from(self._vdtor))
		return self._vdtor_calls

	def get_callers(self, write_offset: int = None) -> list[int]:
		if self._callers is None:
			self.make_callers()

		if write_offset is not None:
			rv = self._callers.get(write_offset, None)
			if rv is None: rv = []
			return rv

		retval = set()
		for x in self._callers.values():
			retval.update(x)
		return list(retval)


class CppVtableFactory(p_cont.VtableFactory):
	__instance = None
	def __new__(cls, *args, **kwargs):
		if CppVtableFactory.__instance is not None:
			return CppVtableFactory.__instance

		return super().__new__(cls, *args, **kwargs)

	def __init__(self):
		if CppVtableFactory.__instance is not None:
			return

		super().__init__()
		CppVtableFactory.__instance = self

	def downgrade_classless_vtables(self):
		vid = 0
		for vtbl in self._created_vtables.values():
			if vtbl.get_class() is not None:
				continue
			new_name = "vtable_" + str(vid)
			new_name = p_util.get_next_available_strucname(new_name)
			vtbl.rename(new_name)
			vid += 1
		
	def create_vtable(self, *args, **kwargs):
		vtbl_name = "cpp_vtable_" + str(len(self._created_vtables))
		vtbl_name = p_util.get_next_available_strucname(vtbl_name)
		kwargs["name"] = vtbl_name
		return CppVtable(*args, **kwargs)


class CppClass(p_cont.Struct):
	__slots__ = "_cdtors", "_vtables", "_parents", "_children"
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self._cdtors : set[CDtor] = set()
		self._vtables : dict[int, CppVtable]= {}
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
		current_vtbl = self._vtables.get(offset, None)
		if current_vtbl is not None:
			if current_vtbl != vtbl:
				print("[*] ERROR", self.get_name(), hex(offset), idaapi.get_name(current_vtbl.get_ea()), idaapi.get_name(vtbl.get_ea()))
				raise BaseException("Already have vtbl at this offset")
			return

		self._vtables[offset] = vtbl

	@staticmethod
	def is_cpp_class():
		# TODO
		return False

	def get_parent(self, offset):
		for parent_offset, parent in self._parents.items():
			if parent_offset <= offset and parent_offset + parent.get_size() > offset:
				return parent
		return None

	def get_parent_offset(self, offset):
		for parent_offset, parent in self._parents.items():
			if parent_offset <= offset and parent_offset + parent.get_size() > offset:
				return parent, parent_offset
		return None, None

	def add_parent(self, offset, parent):
		assert isinstance(parent, CppClass), "Trying to add parent, that is not CppClass"

		current_parent = self.get_parent(offset)
		if current_parent is not None:
			assert current_parent == parent, "Already have parent at this offset, and it is a different one"
			return

		if parent.get_size() + offset > self.get_size():
			print("ERROR:", self.get_name(), idaapi.get_name(self.get_vtable(0).get_ea()), hex(offset), parent.get_name(), hex(parent.get_size()), idaapi.get_name(parent.get_vtable(0).get_ea()))
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

		mtif = self.get_member_tinfo(offset)
		if p_cont.VtablesUnion.is_vtables_union(mtif):
			vu = p_cont.VtablesUnion(name=str(mtif))
			vu.add_vtable(vtbl)
			return None

		mname = self.get_member_name(offset)
		# current vtbl --> union [current vtbl , vtbl]
		if mname == "vtable" or mname == "vtable_" + hex(offset)[2:]:
			member_vtbl = self.get_member_tinfo(offset)
			member_vtbl = str(member_vtbl.get_pointed_object())
			member_vtbl = p_cont.Struct(name=member_vtbl)

			vtbl_union_name = "vtables_union_0"
			vtbl_union_name = p_util.get_next_available_strucname(vtbl_union_name)
			vu = p_cont.VtablesUnion(name=vtbl_union_name)
			# need to add vtbl to union first, otherwise ida cant set member type, because its size is 0
			vu.add_vtable(vtbl)
			vu.add_vtable(member_vtbl)
			self.set_member_type(offset, vu.get_name())

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

	def get_tinfo(self):
		tif = idaapi.tinfo_t()
		assert tif.get_named_type(idaapi.get_idati(), self.get_name())
		return tif

	def get_shifted_member_ptr_tinfo(self, offset):
		retval = idaapi.tinfo_t()

		class_tif = self.get_tinfo()
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

			retval = p_util.make_shifted_ptr(class_tif, member_tinfo, offset)

		return retval

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

		factory = CppVtableFactory()
		self._vtbl_writes = {}
		for int_write in p_hrays.ThisUsesVisitor(addr=fea).get_int_writes():
			vtbl = factory.get_vtable(int_write.get_int())
			if vtbl is None:
				continue

			l = self._vtbl_writes.get(int_write.get_offset(), None)
			if l is None:
				l = []
				self._vtbl_writes[int_write.get_offset()] = l
			l.append(vtbl)

	def get_main_vtables(self):
		main_vtables: dict[int, CppVtable] = {}
		for offset, vtbls in self.vtbl_writes():
			if len(vtbls) == 1:  main_vtable = vtbls[0]
			elif self._is_ctor: main_vtable = vtbls[-1]
			elif self._is_dtor: main_vtable = vtbls[0]
			else:                main_vtable = None

			if main_vtable is None:
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
		rv = self._vtbl_writes.get(offset, None)
		if rv is None: rv = []
		return rv

	def get_ea(self):
		return self._fea

	def set_class(self, c):
		if self._cpp_class is not None and self._cpp_class != c:
			raise BaseException("Cdtor already has a class, and it is a different one")
		self._cpp_class = c


class ClassConstructionContext(object):
	__slots__ = "funcea2cdtor"
	def __init__(self):
		self.funcea2cdtor : dict[int, CDtor] = {}

	def clear(self):
		self.funcea2cdtor.clear()

	def cdtors(self):
		for cdtor in self.funcea2cdtor.values():
			yield cdtor

	def add_cdtor(self, fea, cdtor):
		curr = self.funcea2cdtor.get(fea, None)
		assert curr is None, "Already exists for" + idaapi.get_name(fea) + ' ' + idaapi.get_name(curr.get_ea())
		self.funcea2cdtor[fea] = cdtor

	def get_cdtor(self, fea):
		return self.funcea2cdtor.get(fea, None)


class CppClassFactory(object):
	__slots__ = "_vtable_factory", "_created_classes", "_created_unions",\
		"_original_func_types", "_cctx", "user_ctors", "user_dtors"
	__instance = None

	def __new__(cls, *args, **kwargs):
		if cls.__instance is None:
			return super().__new__(cls)
		return cls.__instance

	def __init__(self, *args, **kwargs):
		if CppClassFactory.__instance is not None:
			return
		CppClassFactory.__instance = self

		self._vtable_factory = CppVtableFactory()
		self._created_classes : list[CppClass] = []
		self._created_unions : list[p_cont.VtablesUnion] = []
		self._original_func_types : dict[tuple[int, int], idaapi.tinfo_t] = {}
		self._cctx = ClassConstructionContext()

		self.user_ctors : set[int] = set()
		ctors = kwargs.get("ctors", None)
		if ctors is not None:
			self.user_ctors.update(ctors)

		self.user_dtors : set[int] = set()
		dtors = kwargs.get("dtors", None)
		if dtors is not None:
			self.user_dtors.update(dtors)

	def undo(self):
		print("[*] INFO:", "undoing")
		for (funcea, arg_id), original_func_type in self._original_func_types.items():
			p_func.set_func_argvar_type(funcea, arg_id, original_func_type)

		for v in self._vtable_factory.get_vtables():
			v.delete()

		for c in self._created_classes:
			c.delete()

		for vu in self._created_unions:
			vu.delete()

		self.clear()

	def clear(self):
		self._created_classes.clear()
		self._created_unions.clear()
		self._original_func_types.clear()
		self._cctx.clear()

	def create_all_classes(self):
		self.clear()

		# try:
		self.create_vtables()
		self.create_cdtors()
		self.create_classes()
		CppVtableFactory().downgrade_classless_vtables()

		self.analyze_class_sizes()
		self.analyze_inheritance()
		self.finalize_classes()
		# except:
			# print("[*] ERROR:", sys.exc_info()[0])
			# self.undo()

	def create_vtables(self):
		self._vtable_factory.create_all_vtables()
		print("[*] INFO: found", len(self._vtable_factory.get_vtables()), "vtables")

	def create_cdtors(self):
		all_cdtors = set()
		for vtbl in self._vtable_factory.get_vtables():
			virtual_dtor = vtbl.get_virtual_dtor()
			for c in vtbl.get_callers():
				if c == virtual_dtor:
					continue
				all_cdtors.add(c)

		for cdtor_ea in all_cdtors:
			cdtor = CDtor(cdtor_ea)
			self._cctx.add_cdtor(cdtor_ea, cdtor)

	def create_classes(self):
		for cdtor in self._cctx.cdtors():
			self.analyze_cdtor(cdtor)

		for cdtor in self._cctx.cdtors():
			self.create_class_per_cdtor(cdtor)
		self.analyze_unfinished_cdtors()

	def analyze_cdtor(self, cdtor: CDtor):
		offset0_vtbls = cdtor.get_vtbl_writes(0)
		if len(offset0_vtbls) != 0:
			vtable0 = offset0_vtbls[0]
			if cdtor.get_ea() in vtable0.get_virtual_dtor_calls():
				cdtor._is_dtor = True

		if p_func.get_func_nargs(cdtor.get_ea()) != 1:
			cdtor._is_ctor = True

		if cdtor.get_ea() in self.user_ctors:
			cdtor._is_dtor = False
			cdtor._is_ctor = True

		if cdtor.get_ea() in self.user_dtors:
			cdtor._is_ctor = False
			cdtor._is_dtor = True

		if cdtor._is_dtor and cdtor._is_ctor:
			raise BaseException("Function is both ctor and dtor")

	def create_cpp_class(self):
		class_name = "cpp_class_" + str(len(self._created_classes))
		class_name = p_util.get_next_available_strucname(class_name)
		cpp_class = CppClass(name=class_name)
		self._created_classes.append(cpp_class)
		return cpp_class

	def create_class_per_cdtor(self, cdtor: CDtor):
		main_vtables = cdtor.get_main_vtables()
		if len(main_vtables) == 0:
			return

		cpp_classes = set(filter(None, [v._cpp_class for v in main_vtables.values()]))
		if len(cpp_classes) == 0:
			cpp_class = self.create_cpp_class()
		elif len(cpp_classes) == 1:
			cpp_class = next(iter(cpp_classes))
		else:
			raise BaseException("Several classes for one vtable conflicting")

		for offset, vtbl in main_vtables.items():
			if vtbl._cpp_class is not None: continue
			cpp_class.add_vtable(offset, vtbl)
			vtbl.set_class_offset(cpp_class, offset)

		cpp_class.add_cdtor(cdtor)
		cdtor.set_class(cpp_class)

	def analyze_unfinished_cdtors(self):
		unfinished_cdtors = set([c for c in self._cctx.cdtors() if c.is_unfinished()])
		all_ctors = set([cdtor for cdtor in self._cctx.cdtors() if cdtor._is_ctor])
		all_dtors = set([cdtor for cdtor in self._cctx.cdtors() if cdtor._is_dtor])
		while len(unfinished_cdtors) != 0:
			for u in unfinished_cdtors:
				self.check_cdtor(u, all_ctors, all_dtors)

			new_cdtors = [u for u in unfinished_cdtors if not u.is_unfinished()]
			if len(new_cdtors) == 0:
				break

			for cdtor in new_cdtors:
				self.create_class_per_cdtor(cdtor)

			all_ctors.update([c for c in new_cdtors if c._is_ctor])
			all_dtors.update([d for d in new_cdtors if d._is_dtor])
			unfinished_cdtors = [u for u in unfinished_cdtors if u.is_unfinished()]

	def check_cdtor(self, cdtor, ctors, dtors):
		if cdtor._cpp_class is not None:
			self.check_single_dtor(cdtor)
		self.check_path(cdtor, ctors, dtors)

	def check_path(self, cdtor, ctors, dtors):
		# constructors call constructors, destructors call destructors
		if p_util.got_path(cdtor.get_ea(), ctors):
			cdtor._is_ctor = True
		elif p_util.got_path(cdtor.get_ea(), dtors):
			cdtor._is_dtor = True

	def check_single_dtor(self, cdtor):
		# there can be only one destructor per class, all other are ctors
		if cdtor._cpp_class.get_dtor() is not None:
			cdtor._is_ctor = True

	def analyze_class_sizes(self):
		for cpp_class in self._created_classes:
			sizes = [p_hrays.ThisUsesVisitor(addr=cdtor.get_ea()).get_max_size() for cdtor in cpp_class._cdtors]
			new_class_sz = max(sizes)
			cpp_class.resize(new_class_sz)

	def analyze_inheritance(self):
		for c in self._created_classes:
			for cdtor in c._cdtors:
				self.analyze_cdtor_inheritance(c, cdtor)

		for c in self._created_classes:
			for offset, parent in c._parents.items():
				c.set_member_type(offset, parent.get_name())
				if offset == 0:
					base_name = "base"
				else:
					base_name = "base_" + hex(offset)[2:]
				c.set_member_name(offset, base_name)

		self.set_vtables()

	def analyze_cdtor_inheritance(self, cpp_class, cdtor):
		for offset, vtbls in cdtor.vtbl_writes():
			for vtbl in vtbls:
				if vtbl == cpp_class.get_vtable(offset):
					continue

				parent = vtbl._cpp_class
				if parent is None:
					print("[*] WARNING:", "vtable has no parent class in", idaapi.get_name(cdtor.get_ea()), hex(vtbl.get_ea()))
					continue

				if parent == cpp_class:
					continue

				cpp_class.add_parent(offset, parent)
				parent.add_child(cpp_class)

		for func_call in p_hrays.ThisUsesVisitor(addr=cdtor.get_ea()).get_calls():
			parent_cdtor = self._cctx.get_cdtor(func_call._func_ea)
			if parent_cdtor is None:
				continue

			parent = parent_cdtor._cpp_class
			if parent is None:
				continue

			this_offset = func_call.get_offset(0)
			if this_offset is None:
				continue

			cpp_class.add_parent(this_offset, parent)
			parent.add_child(cpp_class)

	def print_unfinished(self):
		for vtbl in self._vtable_factory.get_vtables():
			if vtbl._cpp_class is None:
				print("[*] WARNING:", "vtable has no cpp class", vtbl.get_name(), idaapi.get_name(vtbl.get_ea()))

		for cpp_class in self._created_classes:
			if len(cpp_class.get_ctors()) == 0:
				print("[*] WARNING: cpp class has no constructors")

			n_dtors = len([x for x in cpp_class._cdtors if x._is_dtor])
			if n_dtors == 0:
				print("[*] WARNING: cpp class has no destructors", idaapi.get_name(cpp_class.get_vtable(0).get_ea()))
			elif n_dtors > 1:
				print(idaapi.get_name(cpp_class.get_vtable(0).get_ea()), [idaapi.get_name(x.get_ea()) for x in cpp_class._cdtors if x._is_dtor])
				raise BaseException("Several destructors found")

		for ucdtor in self._cctx.cdtors():
			name = idaapi.get_name(ucdtor.get_ea())
			if (not ucdtor._is_ctor) and (not ucdtor._is_dtor):
				print("[*] WARNING: function is neither ctor, nor dtor", name)

			if ucdtor._cpp_class is None:
				print("[*] WARNING: cdtor has no cpp class", name)

	def print_classes(self):
		print()
		for c in self._created_classes:
			print("class", hex(c.get_size()), c.get_name())
			print("ctors", [(idaapi.get_name(c.get_ea()), c._is_ctor, c._is_dtor) for c in c._cdtors])
			print("vtbls", [(hex(o), idaapi.get_name(v.get_ea())) for o, v in c._vtables.items()])
			for offset, parent in c._parents.items():
				print("inherits:", hex(offset), parent.get_name(), idaapi.get_name(parent.get_vtable(0).get_ea()))
			print()

	def set_vtables(self):
		for c in self._created_classes:
			for offset, vtbl in c._vtables.items():
				vu = c.set_vtable(offset, vtbl)
				if vu is not None:
					self._created_unions.append(vu)

	def finalize_classes(self):
		for cpp_class in self._created_classes:
			self.update_func_types_in_class(cpp_class)
			for vtbl in cpp_class._vtables.values():
				vtbl.update_func_types()

	def update_func_types_in_class(self, cpp_class):
		new_arg_tinfo = cpp_class.get_shifted_member_ptr_tinfo(0)
		for cdtor in cpp_class._cdtors:
			self.change_this_in_func(new_arg_tinfo, cdtor.get_ea())

		for vtbl_offset, vtbl in cpp_class._vtables.items():
			new_arg_tinfo = cpp_class.get_shifted_member_ptr_tinfo(vtbl_offset)
			parent_vtbl = cpp_class.get_parent_vtable(vtbl_offset)
			self.change_this_in_vtable(new_arg_tinfo, vtbl, parent_vtbl)

	def change_this_in_vtable(self, new_arg_tinfo, vtbl, parent_vtbl=None):
		for member_offset in range(0, vtbl.get_size(), p_util.get_ptr_size()):
			fname = vtbl.get_member_name(member_offset)

			# do not set if found in parent, will be updated later in parent
			if parent_vtbl is not None and parent_vtbl.get_size() > member_offset:
				fname_parent = parent_vtbl.get_member_name(member_offset)
				if fname_parent == fname:
					continue

			fea = idc.get_name_ea_simple(fname)
			if fea == idaapi.BADADDR:
				raise BaseException("Bad name " + fname)
			self.change_this_in_func(new_arg_tinfo, fea)

	def change_this_in_func(self, new_arg_tinfo, func):
		func_tinfo = p_func.get_func_tinfo(func)

		if "__thiscall" not in str(func_tinfo):
			return

		if p_func.get_func_nargs(func) == 0:
			return

		original_func_arg = p_func.get_func_arg_type(func, 0)
		p_func.set_func_argvar_type(func, 0, new_arg_tinfo)
		self._original_func_types[(func, 0)] = original_func_arg