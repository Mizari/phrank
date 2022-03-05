import idaapi
import phrank.phrank_util as p_util
import phrank.phrank_func as p_func
from typing import Optional


ARRAY_FUNCS = {"qmemcpy", "memcpy", "strncpy", "memset", "memmove", "strncat", "strncmp"}
ARRAY_FUNCS.update(['_' + s for s in ARRAY_FUNCS])

WARRAY_FUNCS = {"wcsncat", "wcsncpy"}
WARRAY_FUNCS.update(['_' + s for s in WARRAY_FUNCS])

PRINTF_FUNCS = {"vsnprintf", "snprintf"}
PRINTF_FUNCS.update(['_' + s for s in PRINTF_FUNCS])

HELPER_FUNCS = {"LOWORD", "HIWORD", "LOBYTE"}


def get_last_struct_offset(expr):
	if expr.op != idaapi.cot_memref:
		return None
	return

def get_var_write(expr):
	if expr.op == idaapi.cot_var:
		return expr.v

	if expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_helper:
		func = expr.x.helper
		if func in HELPER_FUNCS:
			arg0 = expr.a[0]
			if arg0.op == idaapi.cot_var:
				return arg0.v

	if expr.op == idaapi.cot_ptr and expr.x.op == idaapi.cot_cast:
		if expr.x.x.op == idaapi.cot_ref and expr.x.x.x.op == idaapi.cot_var:
			return expr.x.x.x.v

	return None

def get_varptr_write_offset(expr):
	if expr.op == idaapi.cot_idx:
		if expr.x.op != idaapi.cot_var or expr.y.op != idaapi.cot_num:
			return None

		return expr.x.v, expr.y.n._value * expr.x.type.get_size()

	if expr.op == idaapi.cot_ptr:
		return get_var_offset(expr.x)

	return None

# trying to get various forms of "var + X", where X is int
def get_var_offset(expr):
	if expr.op == idaapi.cot_cast:
		return get_var_offset(expr.x)

	elif expr.op == idaapi.cot_var:
		return expr.v, 0

	# form ((CASTTYPE*)var) + N
	elif expr.op in [idaapi.cot_add, idaapi.cot_sub]:
		if expr.y.op != idaapi.cot_num:
			return None
		offset = expr.y.n._value
		if expr.op == idaapi.cot_sub:
			offset = - offset

		op_x = expr.x
		if op_x.op == idaapi.cot_var:
			var = op_x.v

		elif op_x.op == idaapi.cot_cast and op_x.x.op == idaapi.cot_var:
			var = op_x.x.v

		else:
			return None

		if op_x.type.is_ptr():
			sz = op_x.type.get_pointed_object().get_size()
			if sz == idaapi.BADSIZE: 
				raise BaseException("Failed to get object's size")
			offset = offset * sz

		return var, offset

	else:
		return None

def get_int(expr):
	if expr.op == idaapi.cot_cast:
		return get_int(expr.x)

	if expr.op == idaapi.cot_ref and expr.x.op == idaapi.cot_obj:
		return expr.x.obj_ea

	if expr.op == idaapi.cot_obj:
		return expr.obj_ea

	if expr.op == idaapi.cot_num:
		return expr.n._value

	return None

class Write:
	__slots__ = "_val"
	def __init__(self, val):
		self._val : Optional[idaapi.cexpr_t] = val

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

class VarWrite(Write):
	__slots__ = "_varref"
	def __init__(self, varref, val):
		super().__init__(val)
		self._varref = varref

	def get_varref(self):
		return self._varref

	def check(self, **kwargs):
		val = kwargs.get("val", None)
		if val is not None and not self.check_val(val):
			return False
		return True

class VarPtrWrite(Write):
	__slots__ = "_offset", "_varref"
	def __init__(self, varref, val, offset):
		super().__init__(val)
		self._varref = varref
		self._offset : Optional[int] = offset

	def get_varref(self):
		return self._varref

	def get_offset(self):
		return self._offset

	def get_int(self):
		return get_int(self._val)

	def check(self, **kwargs):
		offset = kwargs.get("offset", None)
		if offset is not None and self.get_offset() != offset:
			return False

		val = kwargs.get("val", None)
		if val is not None and not self.check_val(val):
			return False
		return True

class FuncCall:
	__slots__ = "_call_expr", "_func_ea", "_func_name", "_this_args"
	def __init__(self, call_expr):
		self._call_expr : idaapi.cexpr_t = call_expr
		self._func_ea : int = idaapi.BADADDR
		self._func_name : Optional[str] = None

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

	def get_arg_var_offset(self, arg_id):
		if len(self._call_expr.a) <= arg_id:
			return None

		arg_expr = self._call_expr.a[arg_id]
		return get_var_offset(arg_expr)

	def get_arg_use_size(self, arg_id=0):
		if arg_id == 0:
			if self._func_name in ARRAY_FUNCS:
				arg2 = self._call_expr.a[2]
				if arg2.op == idaapi.cot_num:
					return arg2.n._value
			elif self._func_name in WARRAY_FUNCS:
				arg2 = self._call_expr.a[2]
				if arg2.op == idaapi.cot_num:
					return arg2.n._value * 2
			elif self._func_name in PRINTF_FUNCS:
				arg2 = self._call_expr.a[1]
				if arg2.op == idaapi.cot_num:
					return arg2.n._value

		elif self._func_ea == idaapi.BADADDR:
			return 0

		# cant look into imported funcs, assume that args are somehow used there
		if p_util.is_func_import(self._func_ea):
			return 1

		if idaapi.get_func(self._func_ea) is None:
			return 0

		return FuncAnalysisVisitor.create(addr=self._func_ea).get_arg_use_size(arg_id)

@p_util.unique(p_func.get_func_start)
class FuncAnalysisVisitor(idaapi.ctree_visitor_t):
	__slots__ = "_writes", "_calls", "_func", "_is_visited"

	def __init__(self, *args, **kwargs):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
		self._varptr_writes : list[VarPtrWrite] = []
		self._var_writes: list[VarWrite] = []
		self._calls : list[FuncCall] = []
		self._func : p_func.FuncWrapper = p_func.FuncWrapper.create(*args, **kwargs)
		self._is_visited = False

	def get_func(self):
		return self._func

	def clear(self):
		self._var_writes.clear()
		self._varptr_writes.clear()
		self._calls.clear()

	def print_uses(self):
		if self._is_visited is False:
			self.visit()

		for w in self._varptr_writes:
			if w.get_int() is not None:
				print("write", hex(w.get_offset()), hex(w.get_int()))
			else:
				print("write", hex(w.get_offset()), w.get_val().opname)

		for c in self._calls:
			print("call", c.get_name(), hex(c.get_offset(0)), c.get_nargs(), c.get_arg_use_size(0), [a.opname for a in c.get_args()])

	def varptr_writes(self, **kwargs):
		if not self._is_visited: self.visit()

		for w in self._varptr_writes:
			if w.check(**kwargs):
				yield w

	def var_writes(self, **kwargs):
		if not self._is_visited: self.visit()
		for w in self._var_writes:
			if w.check(**kwargs):
				yield w

	def get_calls(self):
		if not self._is_visited: self.visit()
		return list(self._calls)

	def visit(self):
		self.clear()
		self._is_visited = True

		try:
			self.apply_to(self._func.get_cfunc().body, None)
		except idaapi.DecompilationFailure:
			print("[*] WARNING", "failed to decompile function", idaapi.get_name(self._func.get_start()), "aborting analysis")

	def visit_expr(self, expr):
		if expr.op == idaapi.cot_asg:
			rv = self.handle_assignment(expr)
		elif expr.op == idaapi.cot_call:
			rv = self.handle_call(expr)
		else:
			rv = False

		return 0

	def get_var_use_size(self, var_id=0):
		if not self._is_visited:
			self.visit()

		max_write_sz = 0
		for w in self._varptr_writes:
			if w.get_varref().idx != var_id:
				continue
			write_sz = w.get_offset() + w.get_write_size()
			if write_sz > max_write_sz:
				max_write_sz = write_sz

		max_func_sz = 0
		for func_call in self._calls:
			var_offset = func_call.get_arg_var_offset(var_id)
			if var_offset is None:
				continue
			var_ref, offset = var_offset
			if var_ref.idx != var_id:
				continue

			call_sz = func_call.get_arg_use_size(var_id)
			if offset + call_sz > max_func_sz:
				max_func_sz = offset + call_sz
		return max(0, max_write_sz, max_func_sz) # zero in case only negative offsets are found

	def get_arg_var(self, arg_id):
		return self._func.get_var(arg_id)

	def get_var(self, var_ref):
		return self._func.get_var(var_ref.idx)

	def handle_call(self, expr):
		fc = FuncCall(call_expr=expr)
		self._calls.append(fc)
		return True

	def handle_assignment(self, expr):
		var_offset = get_varptr_write_offset(expr.x)
		if var_offset is not None:
			varref, offset = var_offset
			w = VarPtrWrite(varref, expr.y, offset)
			self._varptr_writes.append(w)
			return True

		varref = get_var_write(expr.x)
		if varref is not None:
			w = VarWrite(varref, expr.y)
			self._var_writes.append(w)
			return True

		return False

class ThisUsesVisitor:
	__slots__ = "_this_var_offsets", "_fav", "is_this_func"

	def __init__(self, *args, **kwargs):
		addr = p_func.get_func_start(*args, **kwargs)
		if addr is None:
			raise BaseException("Failed to get function start")

		self._fav = FuncAnalysisVisitor.create(*args, **kwargs)
		self._this_var_offsets = {0:0}
		self.is_this_func = self._analyze_this()
		if not self.is_this_func:
			self._this_var_offsets.clear()

	def _analyze_this(self):
		if self._fav._func.get_nargs() == 0:
			return False

		for w in self._fav.var_writes():
			vid = w.get_varref().idx
			if vid == 0:
				return False

			val = w.get_val()
			var_offset = get_var_offset(val)
			if var_offset is None:
				continue
			varref, offset = var_offset
			if varref.idx == 0:
				curr = self._this_var_offsets.get(vid, None)
				if curr is not None:
					return False
				self._this_var_offsets[vid] = offset
		return True

	def get_this_offset(self, varref):
		return self._this_var_offsets.get(varref.idx, None)

	def check_var(self, varref):
		return self.get_this_offset(varref) is not None

	def is_write_to_this(self, write):
		varref = write.get_varref()
		return self.check_var(varref)

	def this_writes(self, **kwargs):
		for w in self._fav.varptr_writes(**kwargs):
			varref = w.get_varref()
			this_offset = self.get_this_offset(varref)
			if this_offset is None:
				continue

			write_offset = w.get_offset() + this_offset
			w = VarPtrWrite(varref, w.get_val(), write_offset)
			yield w

	def get_this_calls(self):
		calls = []
		for func_call in self._fav.get_calls():
			var_offset = func_call.get_arg_var_offset(0)
			if var_offset is None:
				continue

			varref, offset = var_offset
			if not self.check_var(varref):
				continue

			calls.append((offset, func_call))
		return calls

	def get_this_call(self, addr):
		for _, func_call in self.get_this_calls():
			if func_call.get_ea() == addr:
				return func_call