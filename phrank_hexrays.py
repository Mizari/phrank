import idaapi
import phrank_util as p_util
import phrank_func as p_func
from typing import Optional


ARRAY_FUNCS = {"qmemcpy", "memcpy", "strncpy", "memset", "memmove", "strncat", "strncmp"}
ARRAY_FUNCS.update(['_' + s for s in ARRAY_FUNCS])

WARRAY_FUNCS = {"wcsncat", "wcsncpy"}
WARRAY_FUNCS.update(['_' + s for s in WARRAY_FUNCS])

PRINTF_FUNCS = {"vsnprintf", "snprintf"}
PRINTF_FUNCS.update(['_' + s for s in PRINTF_FUNCS])

HELPER_FUNCS = {"LOWORD", "HIWORD", "LOBYTE"}


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

class VarWrite:
	__slots__ = "_var", "_val"
	def __init__(self, var, val):
		self._var = var
		self._val = val

	def get_var(self):
		return self._var

	def get_val(self):
		return self._val

class VarPtrWrite:
	__slots__ = "_offset", "_var", "_val"
	def __init__(self, var, val, offset):
		self._var = var
		self._offset : Optional[int] = offset
		self._val : Optional[idaapi.cexpr_t] = val

	def get_var(self):
		return self._var

	def get_offset(self):
		return self._offset

	def get_val(self):
		return self._val

	def get_int(self):
		return get_int(self._val)

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

		return FuncAnalysisVisitor(addr=self._func_ea).get_arg_use_size(arg_id)

class FuncAnalysisVisitor(idaapi.ctree_visitor_t):
	__slots__ = "_writes", "_calls", "_func", "_is_visited"
	_instances = {}

	def __new__(cls, *args, **kwargs):
		addr = p_func.FuncWrapper(*args, **kwargs).get_start()
		if addr is None:
			raise BaseException("Failed to get function start")

		o = FuncAnalysisVisitor._instances.get(addr, None)
		if o is None:
			o = super().__new__(cls)
		return o

	def __init__(self, *args, **kwargs):
		addr = p_func.FuncWrapper(*args, **kwargs).get_start()
		if addr is None:
			raise BaseException("Failed to get function start")

		# skip init if object was already inited
		if FuncAnalysisVisitor._instances.get(addr, None) is not None: return
		FuncAnalysisVisitor._instances[addr] = self

		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
		self._varptr_writes : list[VarPtrWrite] = []
		self._var_writes: list[VarWrite] = []
		self._calls : list[FuncCall] = []
		self._func = p_func.FuncWrapper(*args, **kwargs)
		self._is_visited = False

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

	def get_writes(self, offset=None, val=None):
		if not self._is_visited: self.visit()

		rv = self._varptr_writes
		if offset is not None:
			rv = [w for w in self._varptr_writes if w.get_offset() == offset]

		if val is not None:
			rv = [w for w in rv if w.get_val() == val]
		return rv

	def get_int_writes(self, offset=None, val=None):
		if not self._is_visited: self.visit()
		return [w for w in self.get_writes(offset=offset) if w.is_int(val)]

	def get_calls(self):
		if not self._is_visited: self.visit()
		return list(self._calls)

	def visit(self):
		self.clear()
		self._is_visited = True

		if self._func.get_cfunc() is None:
			raise BaseException("Function decompilation failed")

		self.apply_to(self._func.get_cfunc().body, None)

	def visit_expr(self, expr):
		if expr.op == idaapi.cot_asg:
			rv = self.handle_assignment(expr)
		elif expr.op == idaapi.cot_call:
			rv = self.handle_call(expr)
		else:
			rv = False

		return 0

	def get_arg_use_size(self, arg_id=0):
		if not self._is_visited:
			self.visit()

		use_var = self.get_arg_var(arg_id)

		max_write_sz = 0
		for w in self._varptr_writes:
			if w.get_var() != use_var:
				continue
			write_sz = w.get_offset() + w.get_write_size()
			if write_sz > max_write_sz:
				max_write_sz = write_sz

		max_func_sz = 0
		for func_call in self._calls:
			var_offset = func_call.get_arg_var_offset(arg_id)
			if var_offset is None:
				continue
			var_ref, offset = var_offset
			arg_var = self.get_var(var_ref)
			if arg_var != use_var:
				continue

			call_sz = func_call.get_arg_use_size(arg_id)
			if offset + call_sz > max_func_sz:
				max_func_sz = offset + call_sz
		return max(0, max_write_sz, max_func_sz) # zero in case only negative offsets are found

	def get_arg_var(self, arg_id):
		return self._func.get_cfunc().arguments[arg_id]

	def get_var(self, var_ref):
		return self._func.get_cfunc().lvars[var_ref.idx]

	def handle_call(self, expr):
		fc = FuncCall(call_expr=expr)
		self._calls.append(fc)
		return True

	def handle_assignment(self, expr):
		var_offset = get_varptr_write_offset(expr.x)
		if var_offset is not None:
			var_ref, offset = var_offset
			var = self.get_var(var_ref)
			w = VarPtrWrite(var, expr.y, offset)
			self._varptr_writes.append(w)
			return True

		var = get_var_write(expr.x)
		if var is not None:
			w = VarWrite(var, expr.y)
			self._var_writes.append(w)
			return True

		return False


class ThisUsesVisitor(FuncAnalysisVisitor):
	__slots__ = "_this_var"

	def __new__(cls, *args, **kwargs):
		addr = p_func.FuncWrapper(*args, **kwargs).get_start()
		if addr is None:
			raise BaseException("Failed to get function start")

		o = ThisUsesVisitor._instances.get(addr, None)
		if o is None:
			o = super().__new__(cls, *args, **kwargs)
		return o

	def __init__(self, *args, **kwargs):
		addr = p_func.FuncWrapper(*args, **kwargs).get_start()
		if addr is None:
			raise BaseException("Failed to get function start")

		# skip init if object was already inited
		if ThisUsesVisitor._instances.get(addr, None) is not None: return
		super().__init__(*args, **kwargs)
		ThisUsesVisitor._instances[addr] = self

		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
		self._this_var = self._func.get_cfunc().arguments[0]

	def check_var(self, var):
		return var == self._this_var