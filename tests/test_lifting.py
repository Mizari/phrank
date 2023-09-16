import phrank


phrank.set_log_debug()
ta = phrank.TypeAnalyzer()
for fea in phrank.iterate_all_functions():
	ta.get_tfg(fea)