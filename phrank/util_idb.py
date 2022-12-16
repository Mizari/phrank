import idaapi

VOIDPTR_TIF = idaapi.tinfo_t()
idaapi.parse_decl(VOIDPTR_TIF, idaapi.get_idati(), "void*;", 0)
assert VOIDPTR_TIF.is_correct()

VOID_FUNC_TIF = idaapi.tinfo_t()
idaapi.parse_decl(VOID_FUNC_TIF, idaapi.get_idati(), "__int64 (*)();", 0)
assert VOID_FUNC_TIF.is_correct()

if idaapi.get_inf_structure().is_64bit():
	pointer_size = 8
	read_pointer_func = idaapi.get_qword
elif idaapi.get_inf_structure().is_32bit():
	pointer_size = 4
	read_pointer_func = idaapi.get_dword
else:
	pointer_size = 2
	read_pointer_func = idaapi.get_word