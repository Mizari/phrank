from __future__ import annotations

import idaapi
import idautils

from typing import Optional

import phrank.util_aux as util_aux
import phrank.util_ast as p_hrays
import phrank.util_func as util_func

from phrank.containers.vtable import Vtable

class CppVtable(Vtable):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self._vdtor : Optional[int] = None
		self._callers : Optional[dict[int, int]] = None
		self._vdtor_calls : Optional[set[int]] = None
		self._cpp_class = None
		self._cpp_class_offset = idaapi.BADSIZE

	def make_callers(self) -> None:
		callers = [util_aux.get_func_start(x.frm) for x in idautils.XrefsTo(self.get_ea())]
		callers = list(filter(lambda x: x != idaapi.BADADDR, callers))

		self._callers = {}
		for c in callers:
			fuv = p_hrays.ASTAnalysis.create(addr=c)
			writes = [w for w in fuv.varptr_writes(val=self.get_ea())]
			if len(writes) > 1:
				print("[*] WARNING:", "Vtable is written several times to this ptr", idaapi.get_name(c), idaapi.get_name(self.get_ea()))

			if len(writes) == 0:
				print("[*] WARNING:", "Vtable is not used as write to this ptr", idaapi.get_name(c), idaapi.get_name(self.get_ea()))
				continue

			write_offset = writes[0].get_offset()
			l = self._callers.setdefault(write_offset, [])
			l.append(c)

		self._cpp_class = None
		self._cpp_class_offset = None

	def set_class_offset(self, cpp_cls , offset: int) -> None:
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
			if util_func.get_func_nargs(func_addr) != 2:
				return False

			fav: p_hrays.ASTAnalysis = p_hrays.ASTAnalysis.create(addr=func_addr)
			writes = [w for w in fav.get_writes_into_var(0, offset=0, val=vtbl_ea)]
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
				self._vdtor_calls.update(util_aux.get_func_calls_from(self._vdtor))
		return self._vdtor_calls

	def get_callers(self, write_offset: int = None) -> list[int]:
		if self._callers is None:
			self.make_callers()

		if write_offset is not None:
			return self._callers.get(write_offset, [])

		retval = set()
		for x in self._callers.values():
			retval.update(x)
		return list(retval)