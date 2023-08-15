from __future__ import annotations
import idaapi

from pyphrank.type_flow_graph_parts import Var
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

	def print_type_locations(self, needle:str|int|idaapi.tinfo_t):
		if isinstance(needle, int):
			strucid = needle
		elif isinstance(needle, str):
			strucid = utils.str2strucid(needle)
		else:
			strucid = utils.tif2strucid(needle)

		if strucid == -1:
			return

		for var, tif in self.vars.items():
			if utils.tif2strucid(tif) != strucid:
				continue
			print(f"found type in {var}")
		for func_ea, tif in self.retvals.items():
			if utils.tif2strucid(tif) != strucid:
				continue
			print(f"found type in {idaapi.get_name(func_ea)}")