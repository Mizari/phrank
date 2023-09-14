# when creating new vtable should set structure at given EA
SHOULD_SET_VTABLE_TYPES = True

# when decompiling X decompile functions called from X first
# for better type propagation but at the cost of slower analysis
# due to MUCH more decompilations (some might be unnecessary)
DECOMPILE_RECURSIVELY = False

# when decompiling skip functions, that start with these prefixes
FUNCTION_PREFIXES_DECOMPILATION_SKIP_LIST = {
	"nlohmann::",
	"std::",
	"boost::",
	"spdlog::",
	"fmt::",
	"operator delete",
	"operator new",
	"__gnu_internal::",
	"__cxxabiv1::",
	"__gnu_cxx::",
}

def should_skip_by_prefix(fname:str) -> bool:
	for prefix in FUNCTION_PREFIXES_DECOMPILATION_SKIP_LIST:
		if fname.startswith(prefix):
			return True
	return False

PTRSIZE = 8


memset_funcs = {"memset", "_memset"}