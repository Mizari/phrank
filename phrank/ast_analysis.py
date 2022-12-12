from __future__ import annotations

import idaapi

from phrank.ast_parts import *


class ASTAnalysis():
	def __init__(self):
		self.returns : list[ReturnWrapper] = []
		self.calls : list[FuncCall] = []

		self.lvar_writes : list[LvarWrite] = []
		self.lvar_assigns: list[LvarAssign] = []
		self.lvar_reads : list[LvarRead] = []

		self.gvar_assigns : list[GvarAssign] = []
		self.gvar_writes : list[GvarWrite]= []
		self.gvar_reads : list[GvarRead] = []

	def clear(self):
		self.lvar_assigns.clear()
		self.lvar_writes.clear()
		self.calls.clear()
		self.lvar_reads.clear()
		self.returns.clear()

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

	def get_writes_into_lvar(self, var_id):
		for w in self.lvar_writes:
			if w.varid != var_id: continue
			yield w

	def get_lvar_uses_in_calls(self, var_id):
		for func_call in self.calls:
			argid, arg_offset = func_call.get_var_offset()
			if argid != var_id:
				continue

			func_ea = func_call.get_ea()
			if func_ea is not None:
				yield arg_offset, func_ea