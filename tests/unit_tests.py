import idaapi
import idc
import phrank
import time
import os

from typing import Callable


def make_ptr_write(offset, value=None):
	target = phrank.SExpr.create_var_use_chain(-1, phrank.VarUseChain(phrank.Var(-1, 0), phrank.VarUse(offset, phrank.VarUse.VAR_PTR)))
	if value is None:
		value = phrank.SExpr.create_int(-1, 0, phrank.str2tif("int"))
	vw = phrank.VarWrite(target, value)
	return vw

def test_basic_struct_creation() -> bool:
	"""testing new struct with two int fields"""
	var_uses = phrank.VarUses()
	var_uses.writes.append(make_ptr_write(0))
	var_uses.writes.append(make_ptr_write(4))
	sa = phrank.StructAnalyzer()
	t = sa.calculate_var_type_by_uses(var_uses)
	if phrank.is_struct_ptr(t):
		rv = True
	else:
		rv = False
	sa.clear_analysis()
	return rv

def run_test(test_func:Callable[[], bool]):
	code = test_func.__code__
	func_descr = f"{os.path.basename(code.co_filename)}/{test_func.__name__}@{code.co_firstlineno}"

	try:
		assert test_func.__name__.startswith("test_")

		if test_func() is False:
			phrank.log_err(f"{func_descr} failed. doc=\"{test_func.__doc__}\"")
	except Exception as e:
		phrank.log_err(f"{func_descr} raised {e}. doc={test_func.__doc__}")

def run_all_tests():
	run_test(test_basic_struct_creation)


def main():
	idaapi.auto_wait()

	log_file = idc.ARGV[1]
	phrank.set_log_file(log_file)
	phrank.set_log_debug()

	t0 = time.time()
	run_all_tests()
	t1 = time.time()
	phrank.log_info(f"unit tests finished in {t1 - t0}")

	idaapi.qexit(0)


if __name__ == "__main__":
	main()