import idaapi
import idc

import phrank.util_aux as util_aux

from phrank.containers.cpp_class import CDtor, CppClass
from phrank.containers.vtable import Vtable
from phrank.containers.vtables_union import VtablesUnion
from phrank.analyzers.type_analyzer import TypeAnalyzer
from phrank.analyzers.vtable_analyzer import VtableAnalyzer

class ClassConstructionContext(object):
	def __init__(self):
		self._cdtors : dict[int, CDtor] = {}
		self._vtables : dict[int, Vtable] = {}

	def clear(self):
		self._cdtors.clear()

	def cdtors(self):
		for cdtor in self._cdtors.values():
			yield cdtor

	def add_cdtor(self, cdtor):
		fea = cdtor.get_ea()
		curr = self._cdtors.setdefault(fea, cdtor)
		assert curr == cdtor, "Already exists for" + idaapi.get_name(fea) + ' ' + idaapi.get_name(curr.get_ea())

	def get_cdtor(self, fea):
		return self._cdtors.get(fea, None)

	def add_vtbl(self, vtbl):
		curr = self._vtables.get(vtbl.get_ea(), None)
		if curr is not None:
			if curr != vtbl:
				raise BaseException("Already have vtbl")
			else:
				return

		self._vtables[vtbl.get_ea()] = vtbl

	def get_vtables(self):
		for vtbl in self._vtables.values():
			yield vtbl

	def get_vtable(self, addr):
		return self._vtables.get(addr, None)


class CppClassAnalyzer(TypeAnalyzer):
	def __init__(self, *args, ctors=None, dtors=None, **kwargs):
		super().__init__(*args, **kwargs)
		self._created_classes : list[CppClass] = []
		self._created_unions : list[VtablesUnion] = []
		self._original_func_types : dict[tuple[int, int], idaapi.tinfo_t] = {}

		self._cctx = ClassConstructionContext()
		self.vtbl_analyzer = VtableAnalyzer()

		self.user_ctors : set[int] = set()
		if ctors is not None:
			self.user_ctors.update(ctors)

		self.user_dtors : set[int] = set()
		if dtors is not None:
			self.user_dtors.update(dtors)

	def undo(self):
		print("[*] INFO:", "undoing")

		for (funcea, arg_id), original_func_type in self._original_func_types.items():
			try:
				self.set_func_argvar_type(funcea, arg_id, original_func_type)
			except idaapi.DecompilationFailure:
				args = (idaapi.get_name(funcea), "skipping reverting arg type to", original_func_type)
				print("[*] WARNING", "failed to decompile function", *args)

		for v in self._cctx.get_vtables():
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

	def post_analysis(self):
		self.create_classes()
		self.analyze_class_sizes()
		self.analyze_inheritance()
		self.finalize_classes()

	def analyze_everything(self):
		self.clear()

		# try:

		self.vtbl_analyzer.analyze_everything()
		print("[*] INFO: found", len(self.vtbl_analyzer.new_types), "vtables")
		for vtbl in self.vtbl_analyzer.new_types:
			self.search_vtable(vtbl)

		self.post_analysis()

		# except:
			# print("[*] ERROR:", sys.exc_info()[0])
			# self.undo()

	def analyze_func(self, addr):
		self.search_func(addr)
		self.post_analysis()

	def analyze_vtable(self, vtbl):
		self.search_vtable(vtbl)
		self.post_analysis()

	def search_func(self, func_addr):
		if func_addr in self._cctx._cdtors:
			return

		if not self.is_function_start(func_addr):
			return

		vtbls = set()
		func_fav = self.get_ast_analysis(func_addr)
		for w in func_fav.get_writes_into_var(0):
			intval = w.get_int()
			if intval is None:
				continue

			vtbl = self.vtbl_analyzer.analyze_gvar(intval)
			if vtbl is None:
				continue

			vtbls.add(vtbl)

		if len(vtbls) == 0:
			return

		cdtor = CDtor(func_addr)
		self._cctx.add_cdtor(cdtor)
		for v in vtbls:
			self.search_vtable(v)

		for _, callee_addr in func_fav.get_var_uses_in_calls(0):
			self.search_func(callee_addr)

		for caller_addr in util_aux.get_func_calls_to(func_addr):
			caller_fav = self.get_ast_analysis(caller_addr)
			if any(w[1] == caller_addr for w in caller_fav.get_var_uses_in_calls(0)):
				continue
			self.search_func(caller_addr)

	def search_vtable(self, vtbl):
		if isinstance(vtbl, int):
			addr = vtbl
			vtbl = self.vtbl_analyzer.analyze_gvar(addr)
		elif isinstance(vtbl, Vtable):
			addr = vtbl.get_ea()

		if vtbl is None:
			return

		if self._cctx.get_vtable(addr) is not None:
			return

		self._cctx.add_vtbl(vtbl)

		for caller in vtbl.get_callers():
			if caller == vtbl.get_virtual_dtor():
				continue
			self.search_func(caller)

	def create_classes(self):
		for cdtor in self._cctx.cdtors():
			self.analyze_cdtor(cdtor)

		# first analyze constructors, because destructors might need
		# information about classes in case negative offsets are used
		for cdtor in self._cctx.cdtors():
			if cdtor._is_ctor:
				self.create_class_per_cdtor(cdtor)

		for cdtor in self._cctx.cdtors():
			if not cdtor._is_ctor:
				self.create_class_per_cdtor(cdtor)

		self.analyze_unfinished_cdtors()

	def analyze_cdtor(self, cdtor: CDtor):
		offset0_vtbls = cdtor.get_vtbl_writes(0)
		if len(offset0_vtbls) != 0:
			vtable0 = offset0_vtbls[0]
			if cdtor.get_ea() in vtable0.get_virtual_dtor_calls():
				cdtor._is_dtor = True

		if self.get_func_nargs(cdtor.get_ea()) != 1:
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
		class_name = util_aux.get_next_available_strucname(class_name)
		cpp_class = CppClass(name=class_name)
		self._created_classes.append(cpp_class)
		return cpp_class

	def create_class_per_cdtor(self, cdtor: CDtor):
		fav = self.get_ast_analysis(cdtor.get_ea())
		writes = [w for w in fav.get_writes_into_var(0)]
		if len(writes) == 0:
			print("[*] WARNING", "no writes to thisptr found in cdtor at", idaapi.get_name(cdtor.get_ea()))
			return

		min_offset = min([w.offset for w in writes])
		if min_offset < 0 and cdtor._is_ctor:
			raise BaseException("Negative offset found in constructor " + idaapi.get_name(cdtor.get_ea()))

		main_vtables = cdtor.get_main_vtables()
		if len(main_vtables) == 0:
			print("[*] WARNING", "failed to locate virtual tables in cdtor at", idaapi.get_name(cdtor.get_ea()))
			return

		cpp_classes = set()
		distances = set()
		for offset, vtbl in main_vtables.items():
			if vtbl._cpp_class is None: continue
			cpp_classes.add(vtbl._cpp_class)
			distances.add(offset - vtbl._cpp_class_offset)

		if len(distances) > 1:
			cname = idaapi.get_name(cdtor.get_ea())
			raise BaseException("Several distances found in " + cname)

		if len(cpp_classes) == 0:
			distance = 0
			cpp_class = self.create_cpp_class()
		elif len(cpp_classes) == 1:
			distance = next(iter(distances))
			cpp_class = next(iter(cpp_classes))
		else:
			raise BaseException("Several classes for one vtable conflicting")

		for offset, vtbl in main_vtables.items():
			cpp_class.add_vtable(offset - distance, vtbl)
			vtbl.set_class_offset(cpp_class, offset - distance)

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
		if util_aux.got_path(cdtor.get_ea(), ctors):
			cdtor._is_ctor = True
		elif util_aux.got_path(cdtor.get_ea(), dtors):
			cdtor._is_dtor = True

	def check_single_dtor(self, cdtor):
		# there can be only one destructor per class, all other are ctors
		if cdtor._cpp_class.get_dtor() is not None:
			cdtor._is_ctor = True

	def analyze_class_sizes(self):
		for cpp_class in self._created_classes:
			sizes = [self.get_ast_analysis(cdtor.get_ea()).get_var_use_size(0) for cdtor in cpp_class._cdtors]
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

	def analyze_cdtor_inheritance(self, cpp_class: CppClass, cdtor: CDtor):
		for offset, vtbls in cdtor.vtbl_writes():
			for vtbl in vtbls:
				if vtbl == cpp_class.get_vtable(offset):
					continue

				parent: CppClass = vtbl._cpp_class
				if parent is None:
					print("[*] WARNING:", "vtable has no parent class in", idaapi.get_name(cdtor.get_ea()), hex(vtbl.get_ea()))
					continue

				if cpp_class.get_name() == parent.get_name():
					print("Attempting to make recursive inheritance in %s, skipping" % cpp_class.get_name())
					continue

				if offset <= 0:
					print("Attempting to make inheritance with illegal offset <= 0 (%s), skipping" % offset)
					continue

				cpp_class.add_parent(offset, parent)
				parent.add_child(cpp_class)

		fav = self.get_ast_analysis(cdtor.get_ea())
		for offset, func_call_ea in fav.get_var_uses_in_calls(0):
			parent_cdtor = self._cctx.get_cdtor(func_call_ea)
			if parent_cdtor is None:
				continue

			parent = parent_cdtor._cpp_class
			if parent is None:
				continue

			cpp_class.add_parent(offset, parent)
			parent.add_child(cpp_class)

	def print_unfinished(self):
		for vtbl in self._cctx.get_vtables():
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
		for member_offset in range(0, vtbl.get_size(), util_aux.get_ptr_size()):
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
		func_tinfo = self.get_func_tinfo(func)

		if self.get_func_nargs(func) == 0:
			return

		original_func_arg = self.get_func_arg_type(func, 0)
		try:
			self.set_func_argvar_type(func, 0, new_arg_tinfo)
			self._original_func_types[(func, 0)] = original_func_arg
		except idaapi.DecompilationFailure:
			args = (idaapi.get_name(func), "skipping this arg changing to", new_arg_tinfo)
			print("[*] WARNING", "failed to decompile function", *args)