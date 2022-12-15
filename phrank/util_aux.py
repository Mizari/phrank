import idaapi
import idautils
import idc

ptr_size = None
get_data = None


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

def get_ptr_size():
	global ptr_size
	global get_data

	if ptr_size is None:
		info = idaapi.get_inf_structure()
		if info.is_64bit():
			ptr_size = 8
			get_data = idaapi.get_qword
		elif info.is_32bit():
			ptr_size = 4
			get_data = idaapi.get_dword
		else:
			ptr_size = 2
			get_data = idaapi.get_word

	return ptr_size

def read_ptr(addr):
	global get_data
	global ptr_size

	if get_data is None:
		info = idaapi.get_inf_structure()
		if info.is_64bit():
			ptr_size = 8
			get_data = idaapi.get_qword
		elif info.is_32bit():
			ptr_size = 4
			get_data = idaapi.get_dword
		else:
			ptr_size = 2
			get_data = idaapi.get_word

	return get_data(addr)

def size2dataflags(sz):
	df = {8: idaapi.FF_QWORD, 4: idaapi.FF_DWORD, 2: idaapi.FF_WORD, 1: idaapi.FF_BYTE}.get(sz, 0)
	return df | idaapi.FF_DATA

def iterate_segments():
	for segea in idautils.Segments():
		yield idc.get_segm_start(segea), idc.get_segm_end(segea)