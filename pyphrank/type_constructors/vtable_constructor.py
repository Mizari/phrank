from __future__ import annotations

from pyphrank.type_constructors.type_constructor_interface import ITypeConstructor
from pyphrank.containers.vtable import Vtable


class VtableConstructor(ITypeConstructor):
	def __init__(self) -> None:
		pass

	def from_data(self, addr:int) ->  Vtable|None:
		return Vtable.from_data(addr)