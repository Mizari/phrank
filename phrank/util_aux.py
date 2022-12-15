import idaapi
import idautils
import idc

if idaapi.get_inf_structure().is_64bit():
	pointer_size = 8
	read_pointer_func = idaapi.get_qword
elif idaapi.get_inf_structure().is_32bit():
	pointer_size = 4
	read_pointer_func = idaapi.get_dword
else:
	pointer_size = 2
	read_pointer_func = idaapi.get_word

def split_list(l, cond):
	on_true = []
	on_false = []
	for i in l:
		if cond(i):
			on_true.append(i)
		else:
			on_false.append(i)
	return on_true, on_false

def get_next_available_strucname(strucname):
	while idaapi.get_struc_id(strucname) != idaapi.BADADDR:
		prefix, ctr = strucname.rsplit('_', 1)
		strucname = prefix + '_' + str(int(ctr) + 1)
	return strucname

def size2dataflags(sz):
	df = {8: idaapi.FF_QWORD, 4: idaapi.FF_DWORD, 2: idaapi.FF_WORD, 1: idaapi.FF_BYTE}.get(sz, 0)
	return df | idaapi.FF_DATA

def iterate_segments():
	for segea in idautils.Segments():
		yield idc.get_segm_start(segea), idc.get_segm_end(segea)