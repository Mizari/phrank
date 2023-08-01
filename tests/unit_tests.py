import idaapi
import idc
import phrank
import time
import os
import sys

from typing import Callable


def make_ptr_write(offset, value=None):
	target = phrank.SExpr.create_var_use_chain(-1, phrank.VarUseChain(phrank.Var(0x123456, 0), phrank.VarUse(offset, phrank.VarUse.VAR_PTR)))
	if value is None:
		value = phrank.SExpr.create_int(-1, 0, phrank.str2tif("int"))
	vw = phrank.VarWrite(target, value)
	return vw

def test_basic_struct_creation() -> bool:
	"""testing creating new struct with two int assigns"""
	var_uses = phrank.VarUses()
	var_uses.writes.append(make_ptr_write(0))
	var_uses.writes.append(make_ptr_write(4))
	sa = phrank.TypeAnalyzer()
	if sa.is_var_possible_ptr(var_uses):
		rv = True
	else:
		rv = False
	sa.skip_analysis()
	return rv

def test_basic_struct_content() -> bool:
	"""testing creating struct fields with two int assigns"""
	var_uses = phrank.VarUses()
	var_uses.writes.append(make_ptr_write(0))
	var_uses.writes.append(make_ptr_write(4))
	struc = phrank.Structure.new()
	sa = phrank.TypeAnalyzer()
	sa.container_manager.add_struct(struc)
	sa.add_type_uses_to_var(var_uses, struc.ptr_tinfo)
	if struc.size != 8:
		sa.container_manager.delete_containers()
		return False
	sa.container_manager.delete_containers()
	return True

def test_var_uses_collection() -> bool:
	var = phrank.Var(0x123456, 0)
	mock_analysis = phrank.ASTAnalysis(phrank.ASTCtx(0x123456))
	mock_analysis.assigns.append(make_ptr_write(0))

	ctree_analyzer = phrank.CTreeAnalyzer()
	ta = phrank.TypeAnalyzer(ast_analyzer=ctree_analyzer)
	ta.cache_analysis(mock_analysis)
	vu = ta.get_all_var_uses(var)
	if len(vu) != 1:
		return False
	else:
		return True

def run_test(test_func:Callable[[], bool]):
	code = test_func.__code__
	func_descr = f"{os.path.basename(code.co_filename)}/{test_func.__name__}@{code.co_firstlineno}"

	try:
		if test_func() is False:
			phrank.log_err(f"{func_descr} failed. doc=\"{test_func.__doc__}\"")
	except Exception as e:
		phrank.log_err(f"{func_descr} raised {e}. doc={test_func.__doc__}")


def main():
	idaapi.auto_wait()

	log_file = idc.ARGV[1]
	phrank.set_log_file(log_file)
	phrank.set_log_debug()

	t0 = time.time()
	module = sys.modules[__name__]
	tests = [v for k,v in vars(module).items() if k.startswith("test_")]
	phrank.log_info(f"running {len(tests)} tests")
	for t in tests:
		run_test(t)
	t1 = time.time()

	phrank.log_info(f"unit tests finished in {t1 - t0}")

	idaapi.qexit(0)


if __name__ == "__main__":
	main()