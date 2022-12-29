from __future__ import annotations

import idaapi

from phrank.ast_parts import *


class ASTAnalysis():
	def __init__(self):
		self.returns : list[ReturnWrapper] = []
		self.call_casts : list[CallCast] = []

		self.lvar_assigns : list[VarAssign] = []
		self.lvar_writes  : list[VarWrite]  = []
		self.lvar_reads   : list[VarRead]   = []

		self.gvar_assigns : list[VarAssign] = []
		self.gvar_writes  : list[VarWrite]  = []
		self.gvar_reads   : list[VarRead]   = []

		self.unknown_casts = []
		self.unknown_asgs = []

	def get_returned_lvars(self) -> set[int]:
		returned_lvars = set()
		for r in self.returns:
			ri = r.insn.creturn.expr
			if ri.op == idaapi.cot_cast: ri = ri.x
			if ri.op != idaapi.cot_var: continue
			returned_lvars.add(ri.v.idx)
		return returned_lvars

	def returns_lvar(self, lvar_id: int) -> bool:
		return self.get_returned_lvars() == {lvar_id}

	def iterate_lvar_writes(self, lvar_id:int):
		for w in self.lvar_writes:
			if w.var.varid != lvar_id: continue
			yield w

	def iterat_gvar_writes(self, gvar_id:int):
		for w in self.gvar_writes:
			if w.var.varid != gvar_id: continue
			yield w
		return

	def iterate_lvar_call_casts(self, lvar_id:int):
		for c in self.call_casts:
			if not c.var.is_lvar(lvar_id):
				continue
			yield c

	def iterate_gvar_call_casts(self, gvar_id:int):
		for c in self.call_casts:
			if not c.var.is_gvar(gvar_id):
				continue
			yield c