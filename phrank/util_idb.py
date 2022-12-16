import idaapi


if idaapi.get_inf_structure().is_64bit():
	pointer_size = 8
	read_pointer_func = idaapi.get_qword
elif idaapi.get_inf_structure().is_32bit():
	pointer_size = 4
	read_pointer_func = idaapi.get_dword
else:
	pointer_size = 2
	read_pointer_func = idaapi.get_word