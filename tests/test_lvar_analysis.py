import idaapi
import phrank_api

factory = phrank_api.CFunctionFactory()
analyzer = phrank_api.StructAnalyzer(factory)
factory.decompile_all()
for fea in phrank_api.iterate_all_functions():
	cfunc = factory.get_cfunc(fea)
	if cfunc is None:
		continue
	aa = analyzer.get_ast_analysis(fea)
	for lvar_id in range(analyzer.get_lvars_counter(fea)):
		lvar_type = analyzer.analyze_lvar(fea, lvar_id)
		if lvar_type is phrank_api.UNKNOWN_TYPE:
			print("failed to analyze lvar", analyzer.get_lvar_name(fea, lvar_id), "in", idaapi.get_name(fea))