import idaapi
import phrank_util as p_util
import phrank_func as p_func
from typing import Optional


def get_ptr_var_write_offset(expr):
	if expr.op == idaapi.cot_idx:
		if expr.x.op != idaapi.cot_var or expr.y.op != idaapi.cot_num:
			return None

		return expr.x.v, expr.y.n._value

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

		add_x = expr.x
		if add_x.op == idaapi.cot_var:
			return add_x.v, offset

		if add_x.op != idaapi.cot_cast:
			return None

		cast_type = add_x.type
		cast_expr = add_x.x
		if cast_expr.op != idaapi.cot_var:
			return None

		if cast_type.is_ptr():
			sz = cast_type.get_pointed_object().get_size()
			if sz == idaapi.BADSIZE: 
				raise BaseException("Failed to get object's size")
			return cast_expr.v, offset * sz

		print(cast_expr.opname, expr.y.opname, cast_type.is_ptr())
		raise BaseException("Not implemented: should change offset according to cast type")

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

class ThisWrite:
	__slots__ = "_offset", "_val"
	def __init__(self, val, offset):
		self._offset : Optional[int] = offset
		self._val : Optional[idaapi.cexpr_t] = val

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

ARRAY_SET_FUNCS = {"qmemcpy", "memcpy", "strncpy", "memset"}
ARRAY_SET_FUNCS.update(['_' + s for s in ARRAY_SET_FUNCS])
HELPER_FUNCS = {"LOWORD", "HIWORD", "LOBYTE"}
class ThisFuncCall:
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

	def set_offset(self, arg_id, offset):
		self._this_args[arg_id] = offset

	def get_offset(self, arg_id):
		return self._this_args.get(arg_id, None)

	def get_arg_use_size(self, arg_id):
		if self._func_name in ARRAY_SET_FUNCS:
			return self.handle_array_funcs()

		elif self._func_ea == idaapi.BADADDR:
			return 0

		offset = self.get_offset(arg_id)
		if offset is None:
			return
		
		if idaapi.get_func(self._func_ea) is None:
			return 0

		if p_util.is_func_import(self._func_ea):
			return 0

		return ThisUsesVisitor(addr=self._func_ea).get_max_size()

	def handle_array_funcs(self):
		arg2 = self._call_expr.a[2]
		if arg2.op == idaapi.cot_num:
			return arg2.n._value
		return 0


class ThisUsesVisitor(idaapi.ctree_visitor_t):
	__slots__ = "_writes", "_calls", "_func", "_is_visited"
	_instances = {}

	def __new__(cls, *args, **kwargs):
		addr = p_func.FuncWrapper(*args, **kwargs).get_start()
		if addr is None:
			raise BaseException("Failed to get function start")

		o = ThisUsesVisitor._instances.get(addr, None)
		if o is None:
			o = super().__new__(cls)
		return o

	def __init__(self, *args, **kwargs):
		addr = p_func.FuncWrapper(*args, **kwargs).get_start()
		if addr is None:
			raise BaseException("Failed to get function start")

		# skip init if object was already inited
		if ThisUsesVisitor._instances.get(addr, None) is not None: return
		ThisUsesVisitor._instances[addr] = self

		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
		self._writes : list[ThisWrite] = []
		self._calls : list[ThisFuncCall] = []
		self._func = p_func.FuncWrapper(*args, **kwargs)
		self._is_visited = False

	def clear(self):
		self._writes.clear()
		self._calls.clear()

	def print_uses(self):
		if self._is_visited is False:
			self.visit()

		for w in self._writes:
			if w.get_int() is not None:
				print("write", hex(w.get_offset()), hex(w.get_int()))
			else:
				print("write", hex(w.get_offset()), w.get_val().opname)

		for c in self._calls:
			print("call", c.get_name(), c.get_nargs(), [a.opname for a in c.get_args()])

	def get_writes(self, offset=None, val=None):
		if not self._is_visited: self.visit()

		rv = self._writes
		if offset is not None:
			rv = [w for w in self._writes if w.get_offset() == offset]

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

	def get_max_size(self):
		if not self._is_visited:
			self.visit()

		if len(self._writes) == 0:
			max_write_sz = 0
		else:
			max_write_sz = max([x.get_offset() + x.get_write_size() for x in self._writes])

		max_func_sz = 0
		for func_call in self._calls:
			offset = func_call.get_offset(0)
			if offset is None:
				continue
			call_sz = func_call.get_arg_use_size(0)
			if offset + call_sz > max_func_sz:
				max_func_sz = offset + call_sz
		return max(0, max_write_sz, max_func_sz) # zero in case only negative offsets are found

	def visit_expr(self, expr):
		if expr.op == idaapi.cot_asg:
			rv = self.handle_assignment(expr)
		elif expr.op == idaapi.cot_call:
			rv = self.handle_call(expr)
		else:
			rv = False

		return 0

	def get_var(self, var_ref):
		return self._func.get_cfunc().lvars[var_ref.idx]

	def check_var(self, var):
		return var == self._func.get_cfunc().arguments[0]

	def handle_call(self, expr):
		tfc = ThisFuncCall(call_expr=expr)
		for arg_id, arg in enumerate(expr.a):
			var_offset = get_var_offset(arg)
			if var_offset is None:
				continue

			var_ref, offset = var_offset
			var = self.get_var(var_ref)
			if not self.check_var(var):
				continue

			tfc.set_offset(arg_id, offset)

		self._calls.append(tfc)
		return True

	def handle_assignment(self, expr):
		var_offset = get_ptr_var_write_offset(expr.x)
		if var_offset is None:
			return False
		
		var_ref, offset = var_offset
		var = self._func.get_cfunc().lvars[var_ref.idx]
		if var != self._func.get_cfunc().arguments[0]:
			return False

		w = ThisWrite(expr.y, offset)
		self._writes.append(w)
		return True