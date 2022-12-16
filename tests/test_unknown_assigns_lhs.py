import idaapi
import phrank_api

factory = phrank_api.CFunctionFactory()
factory.decompile_all()
analyzer = phrank_api.ASTAnalyzer()
for fea in phrank_api.iterate_all_functions():
	cfunc = factory.get_cfunc(fea)
	if cfunc is None:
		continue

	aa = analyzer.analyze_cfunc(cfunc)
	if len(aa.unknown_asgs) == 0:
		continue

	print("got", len(aa.unknown_asgs), "unknown assignments in", idaapi.get_name(fea))
	for asg in aa.unknown_asgs:
		print("  ", asg.x.opname)