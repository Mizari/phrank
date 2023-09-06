from __future__ import annotations

from pyphrank.containers.structure import Structure
from pyphrank.type_flow_graph_parts import Var
from pyphrank.type_flow_graph import TFG


class ITypeConstructor:
	def __init__(self) -> None:
		pass

	def from_data(self, addr:int) -> Structure|None:
		return None

	def from_tfg(self, var:Var, tfg:TFG) -> Structure|None:
		return None