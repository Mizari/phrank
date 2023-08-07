import idaapi

from pyphrank.ast_parts import Var
import pyphrank.utils as utils


class AnalysisState:
	def __init__(self) -> None:
		self.vars : dict[Var, idaapi.tinfo_t] = {}
		self.retvals : dict[int, idaapi.tinfo_t] = {}

	def get_var(self, var:Var, default=utils.UNKNOWN_TYPE):
		return self.vars.get(var, default)

	def clear(self):
		self.vars.clear()
		self.retvals.clear()