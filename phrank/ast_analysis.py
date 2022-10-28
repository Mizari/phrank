from __future__ import annotations

import idaapi

from phrank.util_ast import *
import phrank.util_aux as util_aux

class Write:
	def __init__(self, val):
		self._val : idaapi.cexpr_t|None = val

	def get_val(self):
		return self._val

	def is_int(self, val=None):
		intval = get_int(self._val)
		if intval is None:
			return False

		if val is None:
			return True

		return val == intval

	def get_write_size(self):
		sz = self._val.type.get_size()
		if sz == idaapi.BADSIZE:
			raise BaseException("Failed to get write size " + self._val.opname)
		return sz

	def check_val(self, val):
		if isinstance(val, int):
			return self.is_int(val)
		return self.get_val() == val

class VarAccess:
	def __init__(self, varref, offset):
		self.varref = varref
		self.offset = offset

	def get_varref(self):
		return self.varref

	def get_offset(self):
		return self.offset
	
	def get_var_use(self, var_id):
		if self.get_varref().idx != var_id:
			return 0
		else:
			return self.get_offset()

class VarWrite(Write):
	def __init__(self, varref, val):
		super().__init__(val)
		self._varref = varref

	def get_varref(self):
		return self._varref

	def get_varid(self):
		return self._varref.idx

	def check(self, val=None):
		if val is not None and not self.check_val(val):
			return False
		return True

class VarPtrWrite(Write):
	def __init__(self, varref, val, offset):
		super().__init__(val)
		self._varref = varref
		self._offset : int|None = offset

	def get_varref(self):
		return self._varref

	def get_varid(self):
		return self._varref.idx

	def get_offset(self):
		return self._offset

	def get_int(self):
		return get_int(self._val)
	
	def get_var_use(self, var_id):
		if self.get_varref().idx != var_id:
			return 0
		return self.get_offset() + self.get_write_size()

	def check(self, offset=None, val=None):
		if offset is not None and self.get_offset() != offset:
			return False

		if val is not None and not self.check_val(val):
			return False
		return True

class FuncCall:
	def __init__(self, call_expr):
		self._call_expr : idaapi.cexpr_t = call_expr
		self._func_ea : int = idaapi.BADADDR
		self._func_name : str|None = None

		if call_expr.x.op == idaapi.cot_obj:
			self._func_ea = call_expr.x.obj_ea
			self._func_name = idaapi.get_func_name(self._func_ea)
		elif call_expr.x.op == idaapi.cot_helper:
			self._func_name = call_expr.x.helper

		self._this_args : dict[int, int] = {}

	def get_ea(self):
		if self._func_ea == idaapi.BADADDR:
			return None
		return self._func_ea

	def get_nargs(self):
		return len(self._call_expr.a)

	def get_args(self):
		return self._call_expr.a

	def get_name(self):
		return self._func_name

	def get_var_offset(self):
		for arg in self._call_expr.a:
			var_offset = get_var_offset(arg)
			if var_offset is None:
				continue

			var_ref, offset = var_offset
			return var_ref, offset
		return None

	def get_var_use_size(self, var_id=0):
		nargs = self.get_nargs()
		if nargs == 0:
			return 0

		arg0 = self._call_expr.a[0]
		var_offset = get_var_offset(arg0)
		if var_offset is not None:
			var_ref, offset = var_offset
			if var_ref.idx == var_id:
				func_use_value = 0
				if self._func_name in ARRAY_FUNCS:
					arg2 = self._call_expr.a[2]
					if arg2.op == idaapi.cot_num:
						func_use_value = arg2.n._value
				elif self._func_name in WARRAY_FUNCS:
					arg2 = self._call_expr.a[2]
					if arg2.op == idaapi.cot_num:
						func_use_value = arg2.n._value * 2
				elif self._func_name in PRINTF_FUNCS:
					arg2 = self._call_expr.a[1]
					if arg2.op == idaapi.cot_num:
						func_use_value = arg2.n._value

				if func_use_value != 0:
					return offset + func_use_value

		# sanity check
		if self._func_ea == idaapi.BADADDR:
			return 0

		# cant look into imported funcs, assume that args are somehow used there
		if util_aux.is_func_import(self._func_ea):
			return 1

		if idaapi.get_func(self._func_ea) is None:
			return 0

		max_var_use = 0
		for arg_id in range(nargs):
			arg = self._call_expr.a[arg_id]
			var_offset = get_var_offset(arg)
			if var_offset is None:
				continue

			var_ref, offset = var_offset
			if var_ref.idx != var_id:
				continue

			"""
			fav: ASTAnalysis = ASTAnalysis.create(addr=self._func_ea)
			var_use = fav.get_var_use_size(arg_id)
			max_var_use = max(max_var_use, var_use + offset)
			"""
		return max_var_use


class ReturnWrapper:
	def __init__(self, insn) -> None:
		self.insn = insn


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
				print("write", hex(w.get_offset()), hex(w.get_int()))
			else:
				print("write", hex(w.get_offset()), w.get_val().opname)

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
			var_offset = get_var_offset(w.get_val())
			if var_offset is None:
				continue
			varref, offset = var_offset

			vid = w.get_varid()
			if varref.idx == vid:
				continue

			curr = self._var_substitutes.get(vid, None)
			if curr is not None:
				print("[*] WARNING", "var", vid, "is already substituted with", curr[0], "overwriting")
			self._var_substitutes[vid] = (varref.idx, offset)

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
			if w.get_varid() == var_id:
				var_offset = 0
			else:
				var_subst = self.get_var_substitute(w.get_varid())
				if var_subst is not None and var_subst[0] == var_id:
					var_offset = var_subst[1]

			if var_offset is None:
				continue

			write_offset = w.get_offset() + var_offset
			yield VarPtrWrite(w.get_varref(), w.get_val(), write_offset)

	def get_var_uses_in_calls(self, var_id):
		for func_call in self.get_calls():
			arg_offset = func_call.get_var_offset()
			if arg_offset is None:
				continue
			arg_varref, arg_offset = arg_offset

			func_ea = None
			if arg_varref.idx == var_id:
				var_offset = 0
				func_ea = func_call.get_ea()
			else:
				var_offset = self.get_var_substitute_to(arg_varref.idx, var_id)
				if var_offset is not None:
					func_ea = func_call.get_ea()

			if func_ea is not None:
				yield var_offset + arg_offset, func_ea

	def get_var_use_size(self, var_id=0):
		max_access_sz = 0
		for w in self._var_accesses:
			max_access_sz = max(max_access_sz, w.get_var_use(var_id))

		max_write_sz = 0
		for w in self._varptr_writes:
			max_write_sz = max(max_write_sz, w.get_var_use(var_id))

		max_func_sz = 0
		for func_call in self._calls:
			max_func_sz = max(max_func_sz, func_call.get_var_use_size(var_id))
		return max(0, max_write_sz, max_func_sz, max_access_sz) # zero in case only negative offsets are found

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
		var_offset = get_varptr_write_offset(expr.x)
		if var_offset is not None:
			varref, offset = var_offset
			w = VarPtrWrite(varref, expr.y, offset)
			self._varptr_writes.append(w)

		else:
			varref = get_var_write(expr.x)
			if varref is not None:
				w = VarWrite(varref, expr.y)
				self._var_writes.append(w)

			else:
				self.apply_to(expr.x, None)

		self.apply_to(expr.y, None)

		return True

	def handle_expr(self, expr):
		var_access = get_var_access(expr)
		if var_access is not None:
			varref, offset = var_access
			w = VarAccess(varref, offset)
			self._var_accesses.append(w)
			return True

		return False