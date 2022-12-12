from __future__ import annotations

import idaapi

from phrank.ast_parts import *


class ASTAnalysis():
	def __init__(self):
		self.returns : list[ReturnWrapper] = []
		self.calls : list[FuncCall] = []

		self.lvar_writes : list[LvarWrite] = []
		self.lvar_assigns: list[LvarAssign] = []
		self.lvar_substitutes = {} # var_id_i -> (var_id_j, offset). for situations like "Vi = Vj + offset"
		self.lvar_reads : list[LvarRead] = []

		self.gvar_assigns : list[GvarAssign] = []
		self.gvar_writes : list[GvarWrite]= []
		self.gvar_reads : list[GvarRead] = []

	def clear(self):
		self.lvar_assigns.clear()
		self.lvar_writes.clear()
		self.calls.clear()
		self.lvar_reads.clear()
		self.lvar_substitutes.clear()
		self.returns.clear()

	def print_uses(self):
		for w in self.lvar_writes:
			if w.get_int() is not None:
				print("write", hex(w.offset), hex(w.get_int()))
			else:
				print("write", hex(w.offset), w.val.opname)

		for c in self.calls:
			print("call", c.get_name(), hex(c.get_offset(0)), c.get_nargs(), c.get_var_use_size(0), [a.opname for a in c.get_args()])

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

	def get_lvar_substitute(self, varid):
		return self.lvar_substitutes.get(varid, None)

	def get_lvar_substitute_to(self, varid_from, varid_to):
		var_subst = self.lvar_substitutes.get(varid_from, None)
		if var_subst is None:
			return None

		var_id, var_offset = var_subst
		if var_id != varid_to:
			return None
		return var_offset

	def get_writes_into_lvar(self, var_id):
		for w in self.lvar_writes:
			var_offset = None
			if w.varid == var_id:
				var_offset = 0
			else:
				var_subst = self.get_lvar_substitute(w.varid)
				if var_subst is not None and var_subst[0] == var_id:
					var_offset = var_subst[1]

			if var_offset is None:
				continue

			write_offset = w.offset + var_offset
			yield LvarWrite(w.varid, w.val, write_offset)

	def get_lvar_uses_in_calls(self, var_id):
		for func_call in self.calls:
			argid, arg_offset = func_call.get_var_offset()
			if argid == -1:
				continue

			func_ea = None
			if argid == var_id:
				var_offset = 0
				func_ea = func_call.get_ea()
			else:
				var_offset = self.get_lvar_substitute_to(argid, var_id)
				if var_offset is not None:
					func_ea = func_call.get_ea()

			if func_ea is not None:
				yield var_offset + arg_offset, func_ea