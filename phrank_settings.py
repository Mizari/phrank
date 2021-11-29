DECOMPILE_RECURSIVELY = True
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