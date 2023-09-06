from __future__ import annotations

from pyphrank.type_flow_graph_parts import Var
from pyphrank.type_constructors.type_constructor_interface import ITypeConstructor
from pyphrank.containers.structure import Structure
from pyphrank.type_flow_graph import TFG


from typing import TYPE_CHECKING

if TYPE_CHECKING:
	from pyphrank.type_analyzer import TypeAnalyzer
	pass

class StructConstructor(ITypeConstructor):
	def __init__(self, type_analyzer:TypeAnalyzer) -> None:
		self.ta = type_analyzer

	def from_tfg(self, var:Var, tfg: TFG) -> Structure | None:
		if not self.ta.is_var_possible_ptr(var, tfg):
			return None

		return Structure.new()