import phrank_api

factory = phrank_api.CFunctionFactory()
analyzer = phrank_api.StructAnalyzer(factory)
factory.decompile_all()

all_gvars = set()
for fea in phrank_api.iterate_all_functions():
	cfunc = factory.get_cfunc(fea)
	if cfunc is None:
		continue
	aa = analyzer.get_ast_analysis(fea)
	for gvar_write in aa.gvar_writes:
		all_gvars.add(gvar_write.varid)
	for gvar_assign in aa.gvar_assigns:
		all_gvars.add(gvar_assign.varid)

print("found", len(all_gvars), "gvars")
for addr in all_gvars:
	analyzer.analyze_gvar(addr)
	gvar_type = analyzer.gvar2tinfo[addr]
	if gvar_type is phrank_api.UNKNOWN_TYPE:
		print("failed to analyze", hex(addr))
	else:
		print("analyzed", hex(addr), "as", str(gvar_type))