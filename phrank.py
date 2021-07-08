import idaapi
import tempfile
import os

idaapi.require("phrank_func")
idaapi.require("phrank_cpp")
idaapi.require("phrank_containers")
idaapi.require("phrank_hexrays")
idaapi.require("phrank_util")
import phrank_cpp


def decompile_all_functions():
	temp_file, temp_filename = tempfile.mkstemp()
	os.close(temp_file)
	idaapi.decompile_many(temp_filename, None, 0)
	os.remove(temp_filename)

def main():
	# decompile_all_functions()

	fact = phrank_cpp.CppClassFactory()
	fact.create_all_classes()

	idaapi.refresh_idaview_anyway()

if __name__ == "__main__":
	main()