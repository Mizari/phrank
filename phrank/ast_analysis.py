from __future__ import annotations

import idaapi

from phrank.util_ast import *


class ASTAnalysis(idaapi.ctree_visitor_t):
	def __init__(self, cfunc: idaapi.cfunc_t|None = None):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)

		self._returns : list[ReturnWrapper] = []
		self._varptr_writes : list[VarPtrWrite] = []
		self._var_writes: list[VarWrite] = []
		self._var_substitutes = {} # var_id_i -> (var_id_j, offset). for situations like "Vi = Vj + offset"
		self._var_accesses : list[VarAccess] = []
		self._calls : list[FuncCall] = []

		if cfunc is not None:
			self.visit(cfunc)

	def clear(self):
		self._var_writes.clear()
		self._varptr_writes.clear()
		self._calls.clear()
		self._var_accesses.clear()
		self._var_substitutes.clear()
		self._returns.clear()

	def print_uses(self):
		for w in self._varptr_writes:
			if w.get_int() is not None:
				print("write", hex(w.offset), hex(w.get_int()))
			else:
				print("write", hex(w.offset), w.val.opname)

		for c in self._calls:
			print("call", c.get_name(), hex(c.get_offset(0)), c.get_nargs(), c.get_var_use_size(0), [a.opname for a in c.get_args()])

	def varptr_writes(self, offset=None, val=None):
		for w in self._varptr_writes:
			if w.check(offset, val):
				yield w

	def iterate_returns(self):
		for r in self._returns:
			yield r

	def get_returned_lvars(self) -> set[int]:
		returned_lvars = set()
		for r in self._returns:
			ri = r.insn.creturn.expr
			if ri.op == idaapi.cot_cast: ri = ri.x
			if ri.op != idaapi.cot_var: continue
			returned_lvars.add(ri.v.idx)
		return returned_lvars

	def returns_lvar(self, lvar_id: int) -> bool:
		return self.get_returned_lvars() == {lvar_id}

	def var_writes(self, val=None):
		for w in self._var_writes:
			if w.check(val=val):
				yield w

	def get_calls(self):
		return list(self._calls)

	def visit(self, cfunc: idaapi.cfunc_t):
		self.apply_to(cfunc.body, None)

		for w in self.var_writes():
			varid, offset = get_var_offset(w.val)
			if varid == -1:
				continue

			vid = w.varid
			if varid == vid:
				continue

			curr = self._var_substitutes.get(vid, None)
			if curr is not None:
				print("[*] WARNING", "var", vid, "is already substituted with", curr[0], "overwriting")
			self._var_substitutes[vid] = (varid, offset)

	def get_var_substitute(self, varid):
		return self._var_substitutes.get(varid, None)

	def get_var_substitute_to(self, varid_from, varid_to):
		var_subst = self._var_substitutes.get(varid_from, None)
		if var_subst is None:
			return None

		var_id, var_offset = var_subst
		if var_id != varid_to:
			return None
		return var_offset

	def visit_insn(self, insn):
		should_prune = False
		if insn.op == idaapi.cit_return:
			should_prune = self.handle_return(insn)

		if should_prune:
			self.prune_now()

		return 0

	def visit_expr(self, expr):
		if expr.op == idaapi.cot_asg:
			should_prune = self.handle_assignment(expr)
		elif expr.op == idaapi.cot_call:
			should_prune = self.handle_call(expr)
		else:
			should_prune = self.handle_expr(expr)

		if should_prune:
			self.prune_now()

		return 0

	def get_writes_into_var(self, var_id, offset=None, val=None):
		for w in self.varptr_writes(offset, val):
			var_offset = None
			if w.varid == var_id:
				var_offset = 0
			else:
				var_subst = self.get_var_substitute(w.varid)
				if var_subst is not None and var_subst[0] == var_id:
					var_offset = var_subst[1]

			if var_offset is None:
				continue

			write_offset = w.offset + var_offset
			yield VarPtrWrite(w.varid, w.val, write_offset)

	def get_var_uses_in_calls(self, var_id):
		for func_call in self.get_calls():
			argid, arg_offset = func_call.get_var_offset()
			if argid == -1:
				continue

			func_ea = None
			if argid == var_id:
				var_offset = 0
				func_ea = func_call.get_ea()
			else:
				var_offset = self.get_var_substitute_to(argid, var_id)
				if var_offset is not None:
					func_ea = func_call.get_ea()

			if func_ea is not None:
				yield var_offset + arg_offset, func_ea

	def get_var_use_size(self, var_id):
		var_use_sz = 0
		for w in self._var_accesses:
			var_use_sz = max(var_use_sz, w.get_var_use(var_id))

		for w in self._varptr_writes:
			var_use_sz = max(var_use_sz, w.get_var_use(var_id))

		for func_call in self._calls:
			var_use_sz = max(var_use_sz, func_call.get_var_use_size(var_id))
		return var_use_sz

	def handle_return(self, insn):
		self._returns.append(ReturnWrapper(insn))
		return False

	def handle_call(self, expr):
		fc = FuncCall(call_expr=expr)
		self._calls.append(fc)
		for arg in expr.a:
			self.apply_to_exprs(arg, None)
		return True

	def handle_assignment(self, expr):
		varid, offset = get_varptr_write_offset(expr.x)
		if varid != -1:
			w = VarPtrWrite(varid, expr.y, offset)
			self._varptr_writes.append(w)

		else:
			varid = get_var_write(expr.x)
			if varid != -1:
				w = VarWrite(varid, expr.y)
				self._var_writes.append(w)

			else:
				self.apply_to_exprs(expr.x, None)

		self.apply_to_exprs(expr.y, None)

		return True

	def handle_expr(self, expr):
		varid, offset = get_var_access(expr)
		if varid != -1:
			w = VarAccess(varid, offset)
			self._var_accesses.append(w)
			return True

		return False